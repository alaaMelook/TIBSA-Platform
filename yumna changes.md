# Yumna Changes (Since May 30, 2026)

This document contains a detailed summary of all files changed in the repository since May 30, 2026, including both committed work and uncommitted changes currently in progress.

## 1. Current Uncommitted Changes (Active Development)

These are the files that have been modified recently to fix the Threat Modeling feature and adjust the backend services.

**Deleted Files:**
- `frontend/src/middleware.ts`

**Modified Files:**
- `backend/app/models/threat_modeling.py` (8 insertions, 8 deletions)
- `backend/app/services/asvs_mapping.py` (55 insertions, 1 deletion)
- `backend/app/services/capec_enrichment.py` (145 insertions, 20 deletions)
- `backend/app/services/heatmap_generator.py` (59 insertions, 0 deletions)
- `backend/app/services/llm_summarization.py` (140 insertions, 55 deletions)
- `backend/app/services/stride_rules.py` (617 insertions, 48 deletions)
- `backend/app/services/threat_modeling_engine.py` (471 insertions, 172 deletions)
- `backend/app/services/threat_modeling_service.py` (44 insertions, 13 deletions)
- `frontend/next.config.ts` (9 insertions, 0 deletions)
- `frontend/package-lock.json` (1438 insertions, 1438 deletions)
- `frontend/src/app/dashboard/threat-modeling/page.tsx` (593 insertions, 593 deletions)
- `frontend/src/app/layout.tsx` (24 insertions, 0 deletions)

**Untracked / New Files:**
- `frontend/src/proxy.ts`
- `package-lock.json`

---

## 2. Committed Changes (Since 30/5/2026)

### Commit: `logs history per user edited`
**Date:** Sat May 30 23:07:56 2026 +0300
**Author:** nadine-rasmy23
**Files Changed:**
- `backend/app/api/investigations.py` (17 insertions, 9 deletions)

### Commit: `unneeded files removed`
**Date:** Sat May 30 22:29:33 2026 +0300
**Author:** nadine-rasmy23
**Files Changed:**
- `tibsa_platform.db` (Deleted, 0 bytes)

### Commit: `admin-edits + main branch`
**Date:** Sat May 30 21:33:58 2026 +0300
**Author:** lolo
**Files Changed:**
- `frontend/src/app/dashboard/investigations/[id]/page.tsx` (1 insertion, 1 deletion)

### Commit: `admin-edits + main branch`
**Date:** Sat May 30 21:32:22 2026 +0300
**Author:** lolo
**Files Changed:**
- `frontend/src/types/investigation.ts` (2 insertions, 1 deletion)

### Commit: `Flow 1 is done`
**Date:** Sat May 30 19:25:01 2026 +0300
**Author:** nadine-rasmy23
**Summary:** Large feature commit containing 79 changed files, 10837 insertions(+), 2692 deletions(-).
**Key Files Changed:**
- `.gitignore`
- `Steps.bin`
- `backend/.gitignore`
- `backend/app/api/investigations.py`
- `backend/app/api/scans.py`
- `backend/app/config.py`
- `backend/app/database/base.py`
- `backend/app/database/init_db.py`
- `backend/app/database/session.py`
- `backend/app/main.py`
- `backend/app/models/asset.py`
- `backend/app/models/finding.py`
- `backend/app/models/investigation.py`
- `backend/app/models/ti_report.py`
- `backend/app/models/tm_report.py`
- `backend/app/repositories/finding_repository.py`
- `backend/app/repositories/investigation_repository.py`
- `backend/app/repositories/report_repository.py`
- `backend/app/repositories/user_repository.py`
- `backend/app/routers/website_scanner.py`
- `backend/app/schemas/finding.py`
- `backend/app/schemas/investigation.py`
- `backend/app/schemas/stage_outputs.py`
- `backend/app/services/investigation/ai_reporter.py`
- `backend/app/services/investigation/correlation_engine.py`
- `backend/app/services/investigation/report_exporter.py`
- `backend/app/services/investigation/threat_modeler.py`
- `backend/app/services/investigation/investigation_orchestrator.py`
- `backend/app/services/pentest/modules/auth_security.py`
- `backend/app/services/pentest/modules/cookie_analysis.py`
- `backend/app/services/pentest/modules/directory_discovery.py`
- `backend/app/services/pentest/modules/misconfiguration.py`
- `backend/app/services/pentest/modules/security_headers.py`
- `backend/app/services/pentest/modules/technology_fingerprinting.py`
- `backend/app/services/pentest/utils.py`
- `backend/app/services/scanners/scanner_adapter.py`
- `backend/app/services/threat_context/context_interpreter.py`
- `backend/app/services/threat_intel_service.py`
- `backend/app/services/ti_processing_service.py`
- `backend/app/services/translators/finding_normalizer.py`
- `backend/app/tests/test_correlation_regression_snapshots.py`
- `backend/app/tests/test_investigation_flow.py`
- `backend/app/tests/test_investigation_hardening.py`
- `backend/app/tests/test_normalization.py`
- `backend/app/tests/test_pipeline_stages_4_6.py`
- `backend/requirements.txt`
- `backend/test_ai.py`
- `backend/test_ai_logic.py`
- `backend/test_api.py`
- `backend/test_debug_ai.py`
- `backend/test_fix.py`
- `backend/test_validation.py`
- `backend/tests/test_threat_intel_service.py`
- `backend/tibsa_platform.db`
- `frontend/src/app/dashboard/investigations/[id]/page.tsx`
- `frontend/src/app/dashboard/investigations/page.tsx`
- `frontend/src/app/dashboard/layout.tsx`
- `frontend/src/app/dashboard/page.tsx`
- `frontend/src/app/dashboard/reports/page.tsx`
- `frontend/src/app/dashboard/website-scanner/page.tsx`
- `frontend/src/app/layout.tsx`
- `frontend/src/components/investigation/AttackChainCard.tsx`
- `frontend/src/components/investigation/CollapsibleSection.tsx`
- `frontend/src/components/investigation/FindingsTable.tsx`
- `frontend/src/components/investigation/IOCTable.tsx`
- `frontend/src/components/investigation/InvestigationTimeline.tsx`
- `frontend/src/components/investigation/PentestFindingsView.tsx`
- `frontend/src/components/investigation/RiskGauge.tsx`
- `frontend/src/components/investigation/SOCEventFeed.tsx`
- `frontend/src/components/investigation/TechnicalEvidenceTable.tsx`
- `frontend/src/components/layout/DashboardHeader.tsx`
- `frontend/src/components/layout/Sidebar.tsx`
- `frontend/src/hooks/useInvestigationProgress.ts`
- `frontend/src/lib/api.ts`
- `frontend/src/types/index.ts`
- `frontend/src/types/investigation.ts`
- `tibsa_fake_malware.txt`
