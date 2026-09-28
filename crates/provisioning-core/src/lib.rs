//! Offline, in-memory safe job simulator. Not an execution engine or durable queue.
//! Verified identities deliberately have no production constructors until trusted
//! OIDC/service admission and database-backed job ownership exist.
use std::collections::{BTreeSet, HashMap, HashSet};
use tenant_core::TenantId;

const MAX_OPERATIONS: usize = 128;
const MAX_APPROVAL_SECONDS: u64 = 3_600;
const MAX_LEASE_SECONDS: u64 = 60;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Change {
    Create,
    Update,
    Disable,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Operation {
    pub subscriber_ref: String, // opaque synthetic reference, never a password
    pub change: Change,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DryRun {
    pub tenant: TenantId,
    pub router_id: String,
    pub idempotency_key: String,
    pub operations: Vec<Operation>,
}

/// Only a future reviewed authentication adapter may construct this proof.
/// In this milestone, constructors exist exclusively inside unit tests.
pub struct VerifiedActor {
    tenant: TenantId,
    subject: String,
    routers: BTreeSet<String>,
    can_propose: bool,
    can_approve: bool,
}

/// Dedicated worker identity is likewise deliberately sealed.
pub struct VerifiedWorker {
    id: String,
    tenants: BTreeSet<TenantId>,
    routers: BTreeSet<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JobState {
    AwaitingApproval,
    Approved {
        expires_at: u64,
    },
    Leased {
        worker_id: String,
        epoch: u64,
        expires_at: u64,
    },
    Unknown, // expired lease might have caused an external effect
    Completed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JobError {
    Denied,
    InvalidPlan,
    Capacity,
    KeyConflict,
    NotFound,
    InvalidState,
    SelfApproval,
    InvalidExpiry,
    RouterBusy,
    ExpiredLease,
    InvalidWorker,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lease {
    job_id: u64,
    epoch: u64,
}

struct Job {
    draft: DryRun,
    proposer: String,
    state: JobState,
}

pub struct JobStore {
    jobs: HashMap<u64, Job>,
    keys: HashMap<(TenantId, String), u64>,
    active_routers: HashSet<String>, // global lock: one physical router at a time
    max_jobs: usize,
    next_id: u64,
    next_epoch: u64,
}

fn valid_ref(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= 64
        && v.bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-' || c == b'_')
}

impl JobStore {
    pub fn new(max_jobs: usize) -> Self {
        Self {
            jobs: HashMap::new(),
            keys: HashMap::new(),
            active_routers: HashSet::new(),
            max_jobs,
            next_id: 1,
            next_epoch: 1,
        }
    }

    /// Creates a *synthetic dry run only*; never sends RouterOS commands.
    pub fn submit(&mut self, actor: &VerifiedActor, draft: DryRun) -> Result<u64, JobError> {
        if !actor.can_propose
            || actor.tenant != draft.tenant
            || !actor.routers.contains(&draft.router_id)
        {
            return Err(JobError::Denied);
        }
        let mut refs = HashSet::new();
        if !valid_ref(&draft.router_id)
            || !valid_ref(&draft.idempotency_key)
            || draft.operations.is_empty()
            || draft.operations.len() > MAX_OPERATIONS
            || draft.operations.iter().any(|op| {
                !valid_ref(&op.subscriber_ref) || !refs.insert(op.subscriber_ref.as_str())
            })
        {
            return Err(JobError::InvalidPlan);
        }
        let key = (draft.tenant.clone(), draft.idempotency_key.clone());
        if let Some(&id) = self.keys.get(&key) {
            let existing = self.jobs.get(&id).ok_or(JobError::InvalidState)?;
            return if existing.draft == draft && existing.proposer == actor.subject {
                Ok(id)
            } else {
                Err(JobError::KeyConflict)
            };
        }
        if self.jobs.len() >= self.max_jobs {
            return Err(JobError::Capacity);
        }
        let id = self.next_id;
        self.next_id = id.checked_add(1).ok_or(JobError::Capacity)?;
        self.keys.insert(key, id);
        self.jobs.insert(
            id,
            Job {
                draft,
                proposer: actor.subject.clone(),
                state: JobState::AwaitingApproval,
            },
        );
        Ok(id)
    }

    pub fn approve(
        &mut self,
        checker: &VerifiedActor,
        id: u64,
        now: u64,
        expires_at: u64,
    ) -> Result<(), JobError> {
        let job = self.jobs.get_mut(&id).ok_or(JobError::NotFound)?;
        if checker.tenant != job.draft.tenant
            || !checker.can_approve
            || !checker.routers.contains(&job.draft.router_id)
        {
            return Err(JobError::Denied);
        }
        if checker.subject == job.proposer {
            return Err(JobError::SelfApproval);
        }
        if expires_at
            .checked_sub(now)
            .filter(|v| *v > 0 && *v <= MAX_APPROVAL_SECONDS)
            .is_none()
        {
            return Err(JobError::InvalidExpiry);
        }
        if job.state != JobState::AwaitingApproval {
            return Err(JobError::InvalidState);
        }
        job.state = JobState::Approved { expires_at };
        Ok(())
    }

    /// An execution adapter MUST NOT be wired to this volatile in-memory store.
    pub fn claim(
        &mut self,
        worker: &VerifiedWorker,
        id: u64,
        now: u64,
        lease_seconds: u64,
    ) -> Result<Lease, JobError> {
        let job = self.jobs.get(&id).ok_or(JobError::NotFound)?;
        if !worker.tenants.contains(&job.draft.tenant)
            || !worker.routers.contains(&job.draft.router_id)
        {
            return Err(JobError::InvalidWorker);
        }
        let JobState::Approved { expires_at } = job.state else {
            return Err(JobError::InvalidState);
        };
        if expires_at <= now {
            return Err(JobError::InvalidExpiry);
        }
        if lease_seconds == 0 || lease_seconds > MAX_LEASE_SECONDS {
            return Err(JobError::InvalidExpiry);
        }
        let until = now
            .checked_add(lease_seconds)
            .ok_or(JobError::InvalidExpiry)?;
        if until > expires_at {
            return Err(JobError::InvalidExpiry);
        }
        if self.active_routers.contains(&job.draft.router_id) {
            return Err(JobError::RouterBusy);
        }
        let epoch = self.next_epoch;
        self.next_epoch = epoch.checked_add(1).ok_or(JobError::Capacity)?;
        self.active_routers.insert(job.draft.router_id.clone());
        self.jobs.get_mut(&id).expect("verified job id").state = JobState::Leased {
            worker_id: worker.id.clone(),
            epoch,
            expires_at: until,
        };
        Ok(Lease { job_id: id, epoch })
    }

    pub fn complete(
        &mut self,
        worker: &VerifiedWorker,
        lease: &Lease,
        now: u64,
    ) -> Result<(), JobError> {
        let job = self.jobs.get_mut(&lease.job_id).ok_or(JobError::NotFound)?;
        match &job.state {
            JobState::Leased {
                worker_id,
                epoch,
                expires_at,
            } if worker_id == &worker.id && *epoch == lease.epoch => {
                if now >= *expires_at {
                    return Err(JobError::ExpiredLease);
                }
            }
            _ => return Err(JobError::InvalidWorker),
        }
        self.active_routers.remove(&job.draft.router_id);
        job.state = JobState::Completed;
        Ok(())
    }

    /// Fail closed: never requeue any claimed work after expiry. Reconcile manually.
    pub fn expire(&mut self, now: u64) -> Vec<u64> {
        let mut unknown = Vec::new();
        for (id, job) in &mut self.jobs {
            if matches!(job.state, JobState::Leased { expires_at, .. } if expires_at <= now) {
                // Quarantine the router as well as the job until an audited
                // reconciliation exists. Never allow unrelated automatic work.
                job.state = JobState::Unknown;
                unknown.push(*id);
            }
        }
        unknown.sort_unstable();
        unknown
    }

    /// Tenant-scoped observation (no router identifiers or plan details returned).
    pub fn status(&self, actor: &VerifiedActor, id: u64) -> Result<JobState, JobError> {
        let job = self.jobs.get(&id).ok_or(JobError::NotFound)?;
        if job.draft.tenant != actor.tenant || !actor.routers.contains(&job.draft.router_id) {
            return Err(JobError::NotFound);
        }
        Ok(job.state.clone())
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    fn tenant(s: &str) -> TenantId {
        TenantId::parse(s).unwrap()
    }
    fn actor(t: &str, subject: &str, propose: bool, approve: bool) -> VerifiedActor {
        VerifiedActor {
            tenant: tenant(t),
            subject: subject.into(),
            routers: BTreeSet::from(["r1".into()]),
            can_propose: propose,
            can_approve: approve,
        }
    }
    fn worker(t: &str, name: &str) -> VerifiedWorker {
        VerifiedWorker {
            id: name.into(),
            tenants: BTreeSet::from([tenant(t)]),
            routers: BTreeSet::from(["r1".into()]),
        }
    }
    fn plan(t: &str, key: &str) -> DryRun {
        DryRun {
            tenant: tenant(t),
            router_id: "r1".into(),
            idempotency_key: key.into(),
            operations: vec![Operation {
                subscriber_ref: "customer-001".into(),
                change: Change::Create,
            }],
        }
    }
    fn approved(store: &mut JobStore, key: &str) -> u64 {
        let id = store
            .submit(
                &actor("kangnet", "maker", true, false),
                plan("kangnet", key),
            )
            .unwrap();
        store
            .approve(&actor("kangnet", "checker", false, true), id, 100, 300)
            .unwrap();
        id
    }

    #[test]
    fn exactly_identical_retry_reuses_id_conflicting_plan_or_actor_fails() {
        let mut store = JobStore::new(1);
        let maker = actor("kangnet", "maker", true, false);
        let first = store.submit(&maker, plan("kangnet", "key1")).unwrap();
        assert_eq!(store.submit(&maker, plan("kangnet", "key1")), Ok(first));
        let mut changed = plan("kangnet", "key1");
        changed.operations[0].change = Change::Disable;
        assert_eq!(store.submit(&maker, changed), Err(JobError::KeyConflict));
        assert_eq!(
            store.submit(
                &actor("kangnet", "another", true, false),
                plan("kangnet", "key1")
            ),
            Err(JobError::KeyConflict)
        );
        assert_eq!(
            store.submit(&maker, plan("kangnet", "key2")),
            Err(JobError::Capacity)
        );
    }

    #[test]
    fn rejects_unscoped_or_malformed_or_duplicate_dry_run() {
        let mut store = JobStore::new(4);
        assert_eq!(
            store.submit(&actor("nengnet", "p", true, false), plan("kangnet", "k1")),
            Err(JobError::Denied)
        );
        assert_eq!(
            store.submit(&actor("kangnet", "p", false, true), plan("kangnet", "k1")),
            Err(JobError::Denied)
        );
        let maker = actor("kangnet", "p", true, false);
        let mut bad = plan("kangnet", "k1");
        bad.operations.clear();
        assert_eq!(store.submit(&maker, bad), Err(JobError::InvalidPlan));
        let mut bad = plan("kangnet", "k1");
        bad.operations.push(bad.operations[0].clone());
        assert_eq!(store.submit(&maker, bad), Err(JobError::InvalidPlan));
        let mut bad = plan("kangnet", "k1");
        bad.operations[0].subscriber_ref = "real secret\n".into();
        assert_eq!(store.submit(&maker, bad), Err(JobError::InvalidPlan));
        let mut bad = plan("kangnet", "k1");
        bad.idempotency_key = "../unsafe".into();
        assert_eq!(store.submit(&maker, bad), Err(JobError::InvalidPlan));
    }

    #[test]
    fn self_approval_wrong_tenant_expiry_and_repeat_approval_fail() {
        let mut store = JobStore::new(3);
        let maker = actor("kangnet", "maker", true, true);
        let id = store.submit(&maker, plan("kangnet", "k1")).unwrap();
        assert_eq!(
            store.approve(&maker, id, 100, 200),
            Err(JobError::SelfApproval)
        );
        assert_eq!(
            store.approve(&actor("nengnet", "other", false, true), id, 100, 200),
            Err(JobError::Denied)
        );
        let checker = actor("kangnet", "checker", false, true);
        assert_eq!(
            store.approve(&checker, id, 100, 100),
            Err(JobError::InvalidExpiry)
        );
        assert_eq!(
            store.approve(&checker, id, 100, 4_000),
            Err(JobError::InvalidExpiry)
        );
        store.approve(&checker, id, 100, 200).unwrap();
        assert_eq!(
            store.approve(&checker, id, 100, 200),
            Err(JobError::InvalidState)
        );
    }

    #[test]
    fn sealed_worker_is_scoped_and_other_tenant_cannot_inspect() {
        let mut store = JobStore::new(4);
        let id = approved(&mut store, "k1");
        assert_eq!(
            store.status(&actor("nengnet", "e", true, false), id),
            Err(JobError::NotFound)
        );
        assert_eq!(
            store.claim(&worker("nengnet", "w"), id, 101, 20),
            Err(JobError::InvalidWorker)
        );
        assert_eq!(
            store.claim(&worker("kangnet", "w"), id, 300, 20),
            Err(JobError::InvalidExpiry)
        );
        assert_eq!(
            store.claim(&worker("kangnet", "w"), id, 101, 0),
            Err(JobError::InvalidExpiry)
        );
        assert_eq!(
            store.claim(&worker("kangnet", "w"), id, 101, 70),
            Err(JobError::InvalidExpiry)
        );
    }

    #[test]
    fn same_router_cannot_be_leased_twice_even_across_tenants() {
        let mut store = JobStore::new(4);
        let first = approved(&mut store, "k1");
        let second = store
            .submit(
                &actor("nengnet", "maker2", true, false),
                plan("nengnet", "k2"),
            )
            .unwrap();
        store
            .approve(&actor("nengnet", "checker2", false, true), second, 100, 300)
            .unwrap();
        let lease = store
            .claim(&worker("kangnet", "w1"), first, 101, 30)
            .unwrap();
        assert_eq!(
            store.claim(&worker("nengnet", "w2"), second, 102, 30),
            Err(JobError::RouterBusy)
        );
        assert_eq!(
            store.complete(&worker("kangnet", "w1"), &lease, 110),
            Ok(())
        );
        store
            .claim(&worker("nengnet", "w2"), second, 111, 30)
            .unwrap();
    }

    #[test]
    fn wrong_worker_and_repeated_completion_are_rejected() {
        let mut store = JobStore::new(4);
        let id = approved(&mut store, "k1");
        let lease = store.claim(&worker("kangnet", "w1"), id, 101, 20).unwrap();
        assert_eq!(
            store.complete(&worker("kangnet", "w2"), &lease, 102),
            Err(JobError::InvalidWorker)
        );
        store
            .complete(&worker("kangnet", "w1"), &lease, 102)
            .unwrap();
        assert_eq!(
            store.complete(&worker("kangnet", "w1"), &lease, 103),
            Err(JobError::InvalidWorker)
        );
        assert_eq!(
            store.claim(&worker("kangnet", "w1"), id, 104, 20),
            Err(JobError::InvalidState)
        );
    }

    #[test]
    fn timed_out_work_is_unknown_and_never_automatically_replayed() {
        let mut store = JobStore::new(4);
        let id = approved(&mut store, "k1");
        let lease = store.claim(&worker("kangnet", "w1"), id, 101, 20).unwrap();
        assert_eq!(
            store.complete(&worker("kangnet", "w1"), &lease, 121),
            Err(JobError::ExpiredLease)
        );
        assert_eq!(store.expire(121), vec![id]);
        let second = approved(&mut store, "k2");
        assert_eq!(
            store.claim(&worker("kangnet", "w2"), second, 122, 20),
            Err(JobError::RouterBusy)
        );
        assert_eq!(
            store.status(&actor("kangnet", "maker", true, false), id),
            Ok(JobState::Unknown)
        );
        assert_eq!(
            store.claim(&worker("kangnet", "w2"), id, 122, 20),
            Err(JobError::InvalidState)
        );
        assert_eq!(store.expire(122), Vec::<u64>::new());
    }

    #[test]
    fn all_operations_cap_is_enforced_without_execution() {
        let mut store = JobStore::new(4);
        let mut candidate = plan("kangnet", "batch");
        candidate.operations = (0..=MAX_OPERATIONS)
            .map(|n| Operation {
                subscriber_ref: format!("cust-{n}"),
                change: Change::Update,
            })
            .collect();
        assert_eq!(
            store.submit(&actor("kangnet", "maker", true, false), candidate),
            Err(JobError::InvalidPlan)
        );
    }
}
