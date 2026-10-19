"""Sealed Arena Dashboard — Streamlit visualization."""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import httpx
import streamlit as st

# Page config
st.set_page_config(
    page_title="Sealed Arena Dashboard",
    page_icon="🏁",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Constants
REFEREE_URL = os.getenv("REFEREE_URL", "http://localhost:8000")


# ═══════════════════════════════════════════════════════════════════════════
# Helper Functions
# ═══════════════════════════════════════════════════════════════════════════


@st.cache_data(ttl=5)
def fetch_health() -> dict | None:
    """Fetch Referee health status."""
    try:
        resp = httpx.get(f"{REFEREE_URL}/health", timeout=5.0)
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
    return None


@st.cache_data(ttl=5)
def fetch_audit_entries(start: int = 0, limit: int = 50) -> list:
    """Fetch audit log entries."""
    try:
        resp = httpx.get(
            f"{REFEREE_URL}/audit/entries",
            params={"start": start, "end": start + limit},
            timeout=10.0,
        )
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
    return []


@st.cache_data(ttl=5)
def fetch_canary_report() -> dict | None:
    """Fetch canary leakage report."""
    try:
        resp = httpx.get(f"{REFEREE_URL}/canary/report", timeout=10.0)
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
    return None


@st.cache_data(ttl=5)
def fetch_verification() -> dict | None:
    """Fetch audit chain verification status."""
    try:
        resp = httpx.get(f"{REFEREE_URL}/audit/verify", timeout=10.0)
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
    return None


def render_metric_card(title: str, value: str, delta: str | None = None, color: str = "blue") -> None:
    """Render a metric card."""
    st.metric(title, value, delta=delta, delta_color="normal" if color == "green" else "inverse")


# ═══════════════════════════════════════════════════════════════════════════
# Main Dashboard
# ═══════════════════════════════════════════════════════════════════════════


def main() -> None:
    st.title("🏁 Sealed Arena Dashboard")
    st.caption("Adversarial AI Safety Testing Infrastructure — Blind Referee Pattern")

    # Sidebar
    with st.sidebar:
        st.header("Configuration")
        referee_url = st.text_input("Referee URL", value=REFEREE_URL)
        if referee_url != REFEREE_URL:
            os.environ["REFEREE_URL"] = referee_url
            st.rerun()

        st.divider()
        auto_refresh = st.checkbox("Auto-refresh (5s)", value=True)
        if auto_refresh:
            time.sleep(5)
            st.rerun()

        st.divider()
        st.markdown("### Quick Actions")
        if st.button("🔄 Refresh Now"):
            st.rerun()

        if st.button("🔍 Verify Audit Chain"):
            with st.spinner("Verifying..."):
                result = fetch_verification()
                if result:
                    if result["valid"]:
                        st.success("✅ Audit chain valid")
                    else:
                        st.error(f"❌ Chain broken at entry {result['broken_at']}")

    # Main content tabs
    tab1, tab2, tab3, tab4, tab5 = st.tabs(
        ["📊 Overview", "🔗 Audit Chain", "🕵️ Canary Mesh", "🔬 Leak-Lab", "📦 Bundles"]
    )

    # ═══ TAB 1: Overview ═════════════════════════════════════════════════════════
    with tab1:
        st.header("System Overview")

        health = fetch_health()
        if health:
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                render_metric_card("Status", "🟢 Healthy", color="green")
            with col2:
                render_metric_card("Audit Entries", str(health["audit_entries"]))
            with col3:
                render_metric_card("Pending Commitments", str(health["commitments_pending"]))
            with col4:
                render_metric_card("Active Tokens", str(health["tokens_active"]))

            st.divider()

            # Recent activity
            st.subheader("Recent Audit Activity")
            entries = fetch_audit_entries(0, 20)
            if entries:
                for entry in reversed(entries[-10:]):
                    with st.expander(
                        f"{entry['event_type']} — {entry['timestamp'][:19]}",
                        expanded=False,
                    ):
                        st.json(entry["event_data"])
            else:
                st.info("No audit entries yet")
        else:
            st.error("❌ Cannot connect to Referee")
            st.code(f"Expected at: {REFEREE_URL}")

    # ═══ TAB 2: Audit Chain ════════════════════════════════════════════════════════
    with tab2:
        st.header("Tamper-Evident Audit Chain")

        verification = fetch_verification()
        if verification:
            col1, col2 = st.columns(2)
            with col1:
                if verification["valid"]:
                    st.success("✅ **Chain Integrity: VALID**")
                else:
                    st.error(f"❌ **Chain Integrity: BROKEN at entry {verification['broken_at']}**")
            with col2:
                st.metric("Total Entries", verification["total_entries"])

        st.divider()
        st.subheader("Audit Log Entries")

        # Pagination
        col1, col2 = st.columns([3, 1])
        with col2:
            page_size = st.selectbox("Entries per page", [25, 50, 100], index=1)
        with col1:
            page = st.number_input("Page", min_value=0, value=0, step=1)

        entries = fetch_audit_entries(page * page_size, page_size)
        if entries:
            # Display as table
            import pandas as pd

            df = pd.DataFrame([
                {
                    "Index": e["index"],
                    "Time": e["timestamp"][:19],
                    "Event": e["event_type"],
                    "Prev Hash": e["previous_hash"][:16] + "...",
                    "Hash": e["entry_hash"][:16] + "...",
                }
                for e in entries
            ])
            st.dataframe(df, use_container_width=True, hide_index=True)

            # Detail view
            selected_idx = st.selectbox(
                "Inspect entry",
                options=range(len(entries)),
                format_func=lambda i: f"{entries[i]['event_type']} (idx={entries[i]['index']})",
            )
            if selected_idx is not None:
                st.json(entries[selected_idx]["event_data"])
        else:
            st.info("No entries to display")

    # ═══ TAB 3: Canary Mesh ════════════════════════════════════════════════════════
    with tab3:
        st.header("🕵️ Canary Mesh — Cross-Zone Leakage Detection")

        report = fetch_canary_report()
        if report:
            col1, col2, col3 = st.columns(3)
            with col1:
                score = report["leakage_score"]
                color = "🔴" if score > 50 else "🟡" if score > 10 else "🟢"
                st.metric("Leakage Score", f"{color} {score}/100")
            with col2:
                st.metric("Total Canaries", report["total_canaries"])
            with col3:
                compromised = report["compromised_canaries"]
                st.metric("Compromised", compromised, delta=f"{compromised} leaked" if compromised else "Clean")

            st.divider()

            if report["events"]:
                st.subheader("🚨 Leakage Events")
                for event in report["events"]:
                    severity_color = {
                        "critical": "🔴",
                        "high": "🟠",
                        "medium": "🟡",
                    }.get(event["severity"], "⚪")

                    with st.expander(
                        f"{severity_color} {event['canary']['owner_zone']} → "
                        f"{event['found_in_zone']} ({event['severity']})",
                        expanded=True,
                    ):
                        col1, col2 = st.columns(2)
                        with col1:
                            st.write(f"**Canary:** `{event['canary']['fingerprint']}`")
                            st.write(f"**Owner Zone:** {event['canary']['owner_zone']}")
                            st.write(f"**Found In:** {event['found_in_zone']}")
                            st.write(f"**Severity:** {event['severity']}")
                        with col2:
                            st.write(f"**Detected:** {event['detected_at']}")
                            st.code(event["content_snippet"])
            else:
                st.success("✅ **No cross-zone leakage detected**")
                st.balloons()

            st.divider()
            st.subheader("Severity Breakdown")
            breakdown = report.get("severity_breakdown", {})
            if breakdown:
                import pandas as pd

                df = pd.DataFrame(
                    [(k, v) for k, v in breakdown.items()],
                    columns=["Severity", "Count"],
                )
                st.bar_chart(df.set_index("Severity"))
        else:
            st.warning("Cannot fetch canary report")

    # ═══ TAB 4: Leak-Lab ═══════════════════════════════════════════════════════════
    with tab4:
        st.header("🔬 Leak-Lab — Proof Engine")

        st.markdown("""
        Leak-Lab runs adversarial probes against arena configurations to measure
        observable information leakage. Each probe tests a specific attack vector.
        """)

        col1, col2 = st.columns(2)
        with col1:
            if st.button("🚀 Run Leak-Lab on Sealed Arena", type="primary"):
                with st.spinner("Running probes..."):
                    # In a real implementation, this would call the LeakLab
                    st.info("Leak-Lab execution would run here. Use CLI: `sealed-arena leaklab`")

        with col2:
            if st.button("📊 Compare with Shared Sandbox"):
                with st.spinner("Running comparison..."):
                    st.info("Comparison would run here. Use CLI: `sealed-arena leaklab`")

        st.divider()

        # Expected results table
        st.subheader("Expected Probe Results (Design Targets)")

        probe_data = [
            {
                "Probe": "Cache-Timing",
                "Shared Sandbox": "🔴 LEAKED (4.2 bits)",
                "Sealed Arena": "🟢 BLOCKED (0.0 bits)",
                "Mechanism": "KV-cache salting per tenant",
            },
            {
                "Probe": "Shared Volume",
                "Shared Sandbox": "🔴 LEAKED (8.0 bits)",
                "Sealed Arena": "🟢 BLOCKED (0.0 bits)",
                "Mechanism": "No shared volumes, isolated filesystems",
            },
            {
                "Probe": "Network Scan",
                "Shared Sandbox": "🔴 LEAKED (6.0 bits)",
                "Sealed Arena": "🟢 BLOCKED (0.0 bits)",
                "Mechanism": "Micro-segmented internal networks",
            },
            {
                "Probe": "Timing Oracle",
                "Shared Sandbox": "🔴 LEAKED (1.5 bits)",
                "Sealed Arena": "🟢 BLOCKED (0.0 bits)",
                "Mechanism": "Fixed-cadence response release",
            },
            {
                "Probe": "Canary Mesh",
                "Shared Sandbox": "🔴 LEAKED (6.0 bits)",
                "Sealed Arena": "🟢 BLOCKED (0.0 bits)",
                "Mechanism": "Unique honeytokens per zone",
            },
        ]

        import pandas as pd

        df = pd.DataFrame(probe_data)
        st.dataframe(df, use_container_width=True, hide_index=True)

    # ═══ TAB 5: Bundles ═════════════════════════════════════════════════════════════
    with tab5:
        st.header("📦 Verdict Bundles")

        st.markdown("""
        Verdict bundles are cryptographically signed, tamper-evident packages
        containing the complete audit trail of an arena session. They can be
        verified offline by any third party.
        """)

        # List bundles in current directory
        bundles = list(Path(".").glob("verdict_*.zip"))
        if bundles:
            st.subheader("Available Bundles")
            for bundle in bundles:
                col1, col2, col3 = st.columns([3, 1, 1])
                with col1:
                    st.write(f"📄 `{bundle.name}`")
                with col2:
                    st.write(f"{bundle.stat().st_size / 1024:.1f} KB")
                with col3:
                    if st.button("Verify", key=f"verify_{bundle.name}"):
                        with st.spinner("Verifying..."):
                            from sealed_arena.audit.verify import verify_bundle

                            result = verify_bundle(bundle)
                            if result.overall_valid:
                                st.success("✅ Valid")
                            else:
                                st.error("❌ Invalid")
                                for check in result.checks:
                                    if not check.passed:
                                        st.write(f"  - {check.name}: {check.detail}")
        else:
            st.info("No verdict bundles found. Run a session to generate one.")

        st.divider()

        # Create bundle form
        st.subheader("Create New Bundle")
        with st.form("create_bundle"):
            arena_id = st.text_input("Arena ID", value=f"demo-{int(time.time())}")
            model_snapshot = st.text_input("Model Snapshot ID", value="model-v1")
            seeds = st.text_input("Seeds (comma-separated)", value="seed1,seed2,seed3")

            if st.form_submit_button("Create Bundle"):
                with st.spinner("Creating bundle..."):
                    try:
                        async def create() -> None:
                            async with httpx.AsyncClient(timeout=30.0) as client:
                                resp = await client.post(
                                    f"{REFEREE_URL}/bundle/create",
                                    json={
                                        "arena_id": arena_id,
                                        "model_snapshot_id": model_snapshot,
                                        "seeds": [s.strip() for s in seeds.split(",") if s.strip()],
                                    },
                                )
                                return resp.json()

                        import asyncio

                        result = asyncio.run(create())
                        st.success(f"Bundle created: {result['bundle_path']}")
                        st.rerun()
                    except Exception as e:
                        st.error(f"Failed: {e}")


if __name__ == "__main__":
    main()