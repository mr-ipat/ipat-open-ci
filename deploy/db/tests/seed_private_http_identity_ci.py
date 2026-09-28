"""Seed *only* disposable CI PostgreSQL 16 for signed Rust HTTP integration.
No real credentials, tenant, DNS claims, device data or live VPS modifications.
"""
import os
from test_postgres_rls_integration import TA, TB, sql

ISSUER="https://id.example.invalid/realms/lab"
SUB="synthetic-operator"
def main():
    assert os.getenv("IPAT_PG_EPHEMERAL_TEST")=="1"
    assert os.getenv("PGHOST")=="127.0.0.1"
    assert os.getenv("PGDATABASE")=="ipat_synthetic"
    assert os.getenv("IPAT_PG_SYNTHETIC_PASSWORD")=="local_ci_synthetic_only"
    assert sql("SELECT to_regprocedure('ipat_platform.lookup_active_membership(text,text,uuid,text,text)') IS NOT NULL").stdout.strip()=="t"
    assert sql("SELECT to_regrole('ipat_lab_identity_reader') IS NULL").stdout.strip()=="t"
    sql("""CREATE ROLE ipat_lab_identity_reader LOGIN INHERIT
      NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
      PASSWORD 'local_ci_synthetic_only'""")
    sql("GRANT ipat_identity_query TO ipat_lab_identity_reader")
    assert sql("SELECT to_regrole('ipat_lab_device_registrar') IS NULL").stdout.strip()=="t"
    sql("""CREATE ROLE ipat_lab_device_registrar LOGIN INHERIT
      NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
      PASSWORD 'local_ci_synthetic_only'""")
    sql("GRANT ipat_device_registry_execute TO ipat_lab_device_registrar")
    sql(f"""INSERT INTO ipat_platform.identity_memberships
       (tenant_id,issuer,subject,role,approved_by,expires_at) VALUES
       ('{TA}','{ISSUER}','{SUB}','noc_engineer','CI-APPROVED-A',
          statement_timestamp() + interval '1 day'),
       ('{TB}','{ISSUER}','{SUB}','helpdesk','CI-APPROVED-B',
          statement_timestamp() + interval '1 day'),
       ('{TB}','{ISSUER}','{SUB}','noc_engineer','CI-APPROVED-B-NOC',
          statement_timestamp() + interval '1 day'),
       ('{TA}','{ISSUER}','{SUB}','tenant_admin','CI-ADMIN-A',
          statement_timestamp() + interval '1 day'),
       ('{TB}','{ISSUER}','{SUB}','tenant_admin','CI-ADMIN-B',
          statement_timestamp() + interval '1 day')""")
    sql(f"""INSERT INTO ipat_platform.identity_pop_grants
       (tenant_id,issuer,subject,role,pop_id) VALUES
       ('{TA}','{ISSUER}','{SUB}','noc_engineer','pop-a'),
       ('{TB}','{ISSUER}','{SUB}','helpdesk','pop-b'),
       ('{TB}','{ISSUER}','{SUB}','noc_engineer','pop-b')""")
    for table in ("identity_memberships","identity_pop_grants","platform_principals"):
        for privilege in ("SELECT","INSERT","UPDATE","DELETE","TRUNCATE"):
            assert sql(f"SELECT has_table_privilege('ipat_lab_identity_reader','ipat_platform.{table}','{privilege}')::int").stdout.strip()=="0"
    assert sql("SELECT has_function_privilege('ipat_lab_identity_reader','ipat_platform.lookup_active_membership(text,text,uuid,text,text)','EXECUTE')::int").stdout.strip()=="1"
    for role in ("ipat_lab_identity_reader","ipat_lab_device_registrar"):
        for privilege in ("SELECT","INSERT","UPDATE","DELETE","TRUNCATE"):
            assert sql(f"""SELECT has_table_privilege(
              '{role}','ipat_ops.device_candidates','{privilege}')::int"""
              ).stdout.strip()=="0"
    write="ipat_platform.propose_lab_device_candidate(text,text,uuid,uuid,text,text,text,text,text,text)"
    read="ipat_platform.list_lab_device_candidates(text,text,uuid,text,text)"
    assert sql(f"""SELECT
      has_function_privilege('ipat_lab_device_registrar','{write}','EXECUTE')::int,
      has_function_privilege('ipat_lab_device_registrar','{read}','EXECUTE')::int,
      has_function_privilege('ipat_lab_identity_reader','{write}','EXECUTE')::int,
      has_function_privilege('ipat_lab_identity_reader','{read}','EXECUTE')::int"""
       ).stdout.strip()=="1|0|0|1"
    # R8.4 distinct VERIFIED signed reviewer (not the tenant-admin maker),
    # only on disposable PostgreSQL. These are fake 2048-bit ephemeral CI keys.
    assert sql("SELECT to_regrole('ipat_lab_device_reviewer') IS NULL").stdout.strip()=="t"
    sql("""CREATE ROLE ipat_lab_device_reviewer LOGIN INHERIT
      NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
      PASSWORD 'local_ci_synthetic_only'""")
    sql("GRANT ipat_device_review_execute TO ipat_lab_device_reviewer")
    sql(f"""INSERT INTO ipat_platform.identity_memberships
      (tenant_id,issuer,subject,role,approved_by,expires_at) VALUES
      ('{TA}','{ISSUER}','synthetic-checker','security_admin','OTHER-CHECKER-A',
         statement_timestamp() + interval '1 day'),
      ('{TB}','{ISSUER}','synthetic-checker','security_admin','OTHER-CHECKER-B',
         statement_timestamp() + interval '1 day'),
      ('{TA}','{ISSUER}','{SUB}','security_admin','SELF-DENIAL-A',
         statement_timestamp() + interval '1 day')""")
    review="ipat_platform.review_lab_device_candidate(text,text,uuid,uuid,uuid,text,text)"
    queue="ipat_platform.list_lab_device_review_queue(text,text,uuid)"
    permit="ipat_platform.lookup_lab_device_reviewer(text,text,uuid)"
    for role in ("ipat_lab_device_reviewer","ipat_lab_identity_reader",
                 "ipat_lab_device_registrar"):
        for table in ("ipat_ops.device_candidates","ipat_ops.device_candidate_reviews",
                      "ipat_platform.identity_memberships"):
            for privilege in ("SELECT","INSERT","UPDATE","DELETE"):
                assert sql(f"""SELECT has_table_privilege(
                  '{role}','{table}','{privilege}')::int""").stdout.strip()=="0"
    assert sql(f"""SELECT
       has_function_privilege('ipat_lab_device_reviewer','{review}','EXECUTE')::int,
       has_function_privilege('ipat_lab_device_reviewer','{queue}','EXECUTE')::int,
       has_function_privilege('ipat_lab_device_reviewer','{permit}','EXECUTE')::int,
       has_function_privilege('ipat_lab_identity_reader','{review}','EXECUTE')::int,
       has_function_privilege('ipat_lab_device_registrar','{review}','EXECUTE')::int"""
       ).stdout.strip()=="1|1|1|0|0"
    # R9.1 separate evidence-attestation identity. Disposable CI ONLY.
    assert sql("SELECT to_regrole('ipat_lab_device_readiness') IS NULL").stdout.strip()=="t"
    sql("""CREATE ROLE ipat_lab_device_readiness LOGIN INHERIT
      NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
      PASSWORD 'local_ci_synthetic_only'""")
    sql("GRANT ipat_device_readiness_execute TO ipat_lab_device_readiness")
    attest="ipat_platform.attest_lab_device_adoption_gate(text,text,uuid,uuid,uuid,text,text,text,text,timestamp with time zone,timestamp with time zone)"
    readiness="ipat_platform.list_lab_device_adoption_readiness(text,text,uuid,text,text)"
    assert sql(f"""SELECT
      has_function_privilege('ipat_lab_device_readiness','{attest}','EXECUTE')::int,
      has_function_privilege('ipat_lab_identity_reader','{attest}','EXECUTE')::int,
      has_function_privilege('ipat_lab_identity_reader','{readiness}','EXECUTE')::int,
      has_function_privilege('ipat_lab_device_readiness','{readiness}','EXECUTE')::int"""
       ).stdout.strip()=="1|0|1|0"
    # R9.2 distinct login used ONLY by actual disposable Rust signed opaque
    # session tests. NO grants to real operators or live VPS PostgreSQL.
    assert sql("SELECT to_regrole('ipat_lab_read_intent_writer') IS NULL").stdout.strip()=="t"
    sql("""CREATE ROLE ipat_lab_read_intent_writer LOGIN INHERIT
      NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
      PASSWORD 'local_ci_synthetic_only'""")
    sql("GRANT ipat_read_intent_execute TO ipat_lab_read_intent_writer")
    intent="ipat_platform.request_lab_read_probe_intent(text,text,uuid,uuid,uuid,text)"
    visible="ipat_platform.list_lab_read_probe_intents(text,text,uuid,text)"
    assert sql(f"""SELECT
      has_function_privilege('ipat_lab_read_intent_writer','{intent}','EXECUTE')::int,
      has_function_privilege('ipat_lab_identity_reader','{intent}','EXECUTE')::int,
      has_function_privilege('ipat_lab_read_intent_writer','{visible}','EXECUTE')::int,
      has_function_privilege('ipat_lab_identity_reader','{visible}','EXECUTE')::int
    """).stdout.strip()=="1|0|0|1"
    for role in ("ipat_lab_identity_reader","ipat_lab_read_intent_writer"):
        for table in ("ipat_ops.device_read_probe_intents",
                      "ipat_ops.device_read_probe_intent_audit"):
            for privilege in ("SELECT","INSERT","UPDATE","DELETE"):
                assert sql(f"""SELECT has_table_privilege(
                  '{role}','{table}','{privilege}')::int""").stdout.strip()=="0"
    print("R92_DISPOSABLE_SEPARATE_NONEXECUTABLE_INTENT_AND_READER")
    print("R91_DISPOSABLE_SEPARATE_READINESS_ATTESTER_AND_READER")
    print("R84_DISPOSABLE_DISTINCT_REVIEWER_DB_AND_MFA_CLAIM_MEMBERSHIPS")
    print("R83_DISPOSABLE_SEPARATE_READER_AND_REGISTER_WRITER_NO_DIRECT_TABLE_ACCESS")
if __name__=="__main__":
    main()
