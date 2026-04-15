import uuid
import time
import logging
from workers.celery_app import celery_app
from models.base import SessionLocal
from models.scan import Finding

logger = logging.getLogger(__name__)


@celery_app.task(
    name="workers.tasks.ai_tasks.generate_ai_fixes",
    queue="ai",
    max_retries=2,
    default_retry_delay=30,
)
def generate_ai_fixes(scan_id: str):
    """
    Generate AI code fixes for all critical/high/medium
    findings. Runs after scan completes.
    """
    db = SessionLocal()
    try:
        from packages.ai.ai_fix_service \
            import AIFixService
        from packages.ai.waf_service \
            import WAFService

        fix_svc = AIFixService()
        waf_svc = WAFService()

        findings = db.query(Finding).filter(
            Finding.scan_id == uuid.UUID(scan_id),
            Finding.attack_worked == True,
            Finding.severity.in_(
                ["critical", "high", "medium"]
            ),
            Finding.ai_fix == None,
        ).all()

        logger.info(
            f"Generating AI fixes for "
            f"{len(findings)} findings "
            f"in scan {scan_id}"
        )

        for finding in findings:
            try:
                fix = fix_svc.generate_fix({
                    "vuln_type":   finding.vuln_type,
                    "severity":    finding.severity,
                    "url":         finding.url,
                    "file_path":   finding.file_path,
                    "line_number": finding.line_number,
                    "evidence":    finding.evidence or "",
                    "description": finding.description or "",
                    "money_loss_min":
                        finding.money_loss_min,
                    "money_loss_max":
                        finding.money_loss_max,
                })

                finding.ai_fix = fix

                # Update money loss from breach DB
                if fix.get("money_loss_min") and \
                   not finding.money_loss_min:
                    finding.money_loss_min = \
                        fix["money_loss_min"]
                if fix.get("money_loss_max") and \
                   not finding.money_loss_max:
                    finding.money_loss_max = \
                        fix["money_loss_max"]

                if fix.get("layman_explanation") and \
                   not finding.layman_explanation:
                    finding.layman_explanation = \
                        fix["layman_explanation"]

                if fix.get("cvss_score") and \
                   not finding.cvss_score:
                    finding.cvss_score = \
                        fix["cvss_score"]

                db.commit()
                logger.info(
                    f"AI fix saved for "
                    f"{finding.id} "
                    f"({finding.vuln_type})"
                )

                # Rate limit — respect API quotas
                time.sleep(1.2)

            except Exception as e:
                logger.error(
                    f"AI fix failed for "
                    f"{finding.id}: {e}"
                )
                # Always save fallback —
                # never leave ai_fix=None
                try:
                    from packages.ai.ai_fix_service \
                        import AIFixService
                    finding.ai_fix = \
                        AIFixService()._fallback_fix({
                            "vuln_type":
                                finding.vuln_type,
                            "severity":
                                finding.severity,
                            "url":
                                finding.url,
                            "file_path":
                                finding.file_path,
                            "evidence":
                                finding.evidence,
                        })
                    db.commit()
                except Exception:
                    pass
                continue

        # WAF rules for critical+high findings
        waf_findings = db.query(Finding).filter(
            Finding.scan_id == uuid.UUID(scan_id),
            Finding.attack_worked == True,
            Finding.severity.in_(
                ["critical", "high"]
            ),
            Finding.waf_rule == None,
        ).all()

        logger.info(
            f"Generating WAF rules for "
            f"{len(waf_findings)} findings"
        )

        for finding in waf_findings:
            try:
                rules = waf_svc.generate_rules({
                    "vuln_type":   finding.vuln_type,
                    "url":         finding.url,
                    "parameter":   finding.parameter,
                    "evidence":    finding.evidence or "",
                })
                finding.waf_rule = rules
                db.commit()
                time.sleep(0.5)
            except Exception as e:
                logger.warning(
                    f"WAF rule failed for "
                    f"{finding.id}: {e}"
                )
                continue

        logger.info(
            f"AI fix generation complete "
            f"for scan {scan_id}"
        )

    except Exception as e:
        logger.error(
            f"AI task failed for scan {scan_id}: {e}",
            exc_info=True,
        )
    finally:
        db.close()
