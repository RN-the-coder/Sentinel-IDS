"""Sentinel IDS v2 — visor SOC de paquetes, alertas y ML educativo."""

from pathlib import Path

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from ml_experiment import run_experiment
from sentinel_data import FIELDS, demo_alerts, demo_telemetry, mask_ip, read_alerts, read_telemetry

ROOT = Path(__file__).resolve().parent
LOG_PATH = ROOT / "ids_alerts.log"
STATUS_PATH = ROOT / "sentinel_status.json"
CYAN, PURPLE, RED, AMBER, GREEN = "#38BDF8", "#A78BFA", "#FB7185", "#FBBF24", "#34D399"

st.set_page_config(page_title="Sentinel IDS · Security Operations", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")

st.markdown("""
<style>
[data-testid="stAppViewContainer"] {background:linear-gradient(140deg,#070F1D,#0D1729 60%,#0B1423);color:#e5edf9;}
[data-testid="stSidebar"] {background:#0B1423;border-right:1px solid #283750;}
[data-testid="stHeader"] {background:transparent;}
.block-container {max-width:1480px;padding-top:1.45rem;padding-bottom:4rem;}
h1,h2,h3 {color:#F1F5FB!important;letter-spacing:-.03em;}
h3 {font-size:1.27rem!important;}
[data-testid="stMetric"] {background:#121F34;border:1px solid #293C57;border-radius:15px;padding:20px 18px;}
[data-testid="stMetricValue"] {color:#EFF8FF;font-weight:700;}
[data-testid="stMetricLabel"] {color:#9EB5CD;}
[data-testid="stDataFrame"] {border:1px solid #293C57;border-radius:13px;}
.hero {padding:26px 30px;border:1px solid #295076;background:radial-gradient(circle at 100% 0%,#16375b,#132840 42%,#10192b 82%);border-radius:19px;margin:0 0 20px 0;}
.kicker {font-size:.73rem;letter-spacing:.21em;font-weight:750;color:#52c5ff;margin-bottom:11px;}
.hero h1 {margin:0 0 6px 0;font-size:2.15rem!important;}
.hero p {margin:0;color:#B2C7DE;font-size:1.03rem;}
.tag {border:1px solid #344b67;border-radius:99px;padding:5px 11px;font-size:.74rem;display:inline-block;margin-top:12px;color:#ADCCE1;}
.note {border:1px solid #2c4864;background:#101E31;border-radius:12px;padding:12px 16px;color:#b6cbe0;font-size:.87rem;margin:8px 0 18px 0;}
.small-muted {color:#91abc2;font-size:.85rem;}
</style>
""", unsafe_allow_html=True)


def plot_style(fig, height=300, legend=False):
    fig.update_layout(
        height=height,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font={"color": "#C8D7E8", "size": 12},
        margin={"l": 12, "r": 12, "t": 30, "b": 12},
        xaxis={"gridcolor": "rgba(120,148,181,.1)", "zeroline": False},
        yaxis={"gridcolor": "rgba(120,148,181,.13)", "zeroline": False},
        showlegend=legend,
        legend={"orientation": "h", "y": -0.25},
        hovermode="x unified",
    )
    return fig


@st.cache_data(ttl=2, show_spinner=False)
def cached_alerts(path, modified):
    return read_alerts(path)


@st.cache_data(ttl=60, show_spinner=False)
def cached_demo():
    return demo_alerts()


def get_alert_data(source):
    if source == "Demostración":
        return cached_demo()
    try:
        mtime = LOG_PATH.stat().st_mtime_ns if LOG_PATH.exists() else 0
        return cached_alerts(str(LOG_PATH), mtime)
    except OSError as exc:
        st.error(f"No se pudo leer el archivo de alertas: {exc}")
        return pd.DataFrame(columns=FIELDS)


def get_status(source):
    if source == "Demostración":
        return "demo", demo_telemetry()
    return read_telemetry(STATUS_PATH)


def render_status(source, state, telemetry):
    if source == "Demostración":
        st.info("🧪 MODO DEMOSTRACIÓN: actividad, alertas e IP ficticias. No representa capturas de tu red.")
    elif state == "activo":
        st.success("🟢 Captura activa · monitoreo real de paquetes TCP/IP · actualización cada 3 segundos")
    elif state == "detenido":
        st.warning("⏸ Captura detenida. Se conservan las estadísticas de la última sesión y los logs históricos.")
    elif state == "atrasado":
        st.warning("⚠️ Telemetría desactualizada. No se puede confirmar que la captura continúe activa.")
    elif state == "error":
        st.error("🔴 El monitor encontró un error. Consulta la terminal donde ejecutaste sentinel_live.py.")
    else:
        st.info("ℹ️ No hay telemetría de captura. Los logs pueden existir aunque el IDS ya esté detenido. Ejecuta sentinel_live.py para habilitar métricas en vivo.")


def traffic_view(telemetry, state):
    st.markdown("### Monitor de tráfico TCP/IP")
    if not telemetry:
        st.markdown('''<div class="note">No se muestran valores de paquetes inventados. Para medir paquetes realmente capturados, inicia <code>sentinel_live.py</code> en lugar de <code>ids.py</code> (solo uno a la vez).</div>''', unsafe_allow_html=True)
        return

    history = pd.DataFrame(telemetry.get("history", []))
    latest = history.iloc[-1] if not history.empty else {}
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Paquetes capturados", f"{int(telemetry.get('packets_total', 0)):,}")
    current_rate = f"{float(latest.get('packets_per_second', 0)):,.1f}" if state in ("activo", "demo") else "—"
    c2.metric("Paquetes / segundo", current_rate)
    c3.metric("Bytes capturados", f"{int(telemetry.get('bytes_total', 0)):,}")
    c4.metric("Paquetes procesados", f"{int(telemetry.get('processed_total', 0)):,}")

    if not history.empty:
        history["timestamp"] = pd.to_datetime(history["timestamp"], errors="coerce")
        history = history.dropna(subset=["timestamp"])
        if not history.empty:
            fig = go.Figure()
            fig.add_trace(go.Scatter(x=history["timestamp"], y=history["packets_per_second"],
                                    name="Paquetes/s", mode="lines", line={"color": CYAN, "width": 3},
                                    fill="tozeroy", fillcolor="rgba(56,189,248,.09)"))
            fig.update_layout(title="Actividad de los últimos 90 segundos", yaxis_title="Paquetes / s")
            st.plotly_chart(plot_style(fig, 275), use_container_width=True)
    st.caption("Datos instrumentados por sentinel_live.py. Solo se miden paquetes IP/TCP; no se almacenan contenidos de paquetes en la telemetría.")
    st.caption(f"Tiempo de sesión: {int(telemetry.get('seconds_running', 0))} s · Último paquete: {telemetry.get('last_packet_at') or 'Sin paquetes observados'}")


def alert_charts(df, masked):
    st.markdown("### Analítica de detecciones")
    if df.empty:
        st.info("No existen alertas para mostrar todavía. Puedes elegir 'Demostración' en la barra lateral.")
        return

    df = df.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df = df.dropna(subset=["timestamp"])
    if df.empty:
        return
    cols = st.columns(4)
    cols[0].metric("Alertas únicas", f"{len(df):,}")
    cols[1].metric("Nivel crítico", f"{(df['severity'] == 'CRITICAL').sum():,}")
    cols[2].metric("IP de origen", f"{df['source_ip'].nunique():,}")
    recent = (df["timestamp"] >= pd.Timestamp.now() - pd.Timedelta(minutes=15)).sum()
    cols[3].metric("Últimos 15 min", f"{recent:,}")

    chart1, chart2 = st.columns([1.7, 1], gap="large")
    with chart1:
        interval = df.set_index("timestamp").resample("5min").size().reset_index(name="alertas")
        fig = go.Figure(go.Scatter(x=interval["timestamp"], y=interval["alertas"],
                                   mode="lines", line={"color": CYAN, "width": 2.6},
                                   fill="tozeroy", fillcolor="rgba(56,189,248,.12)"))
        fig.update_layout(title="Alertas cada 5 minutos")
        st.plotly_chart(plot_style(fig, 300), use_container_width=True)
    with chart2:
        counts = df["rule"].value_counts()
        fig = go.Figure(go.Pie(labels=counts.index.tolist(), values=counts.values.tolist(),
                               hole=.68, marker={"colors": [CYAN, PURPLE, AMBER, RED]},
                               hovertemplate="%{label}: %{value}<extra></extra>"))
        fig.update_layout(title="Reglas activadas")
        st.plotly_chart(plot_style(fig, 300, True), use_container_width=True)

    top = df["source_ip"].value_counts().head(8)
    if masked:
        top.index = [mask_ip(v) for v in top.index]
        top = top.groupby(level=0).sum().sort_values(ascending=False)
    fig = go.Figure(go.Bar(x=top.values, y=top.index, orientation="h", marker_color=PURPLE))
    fig.update_layout(title="Fuentes con mayor número de alertas", yaxis={"autorange": "reversed"})
    st.plotly_chart(plot_style(fig, 285), use_container_width=True)
    st.caption("El IDS original usa reglas demostrativas con falsos positivos. Una alerta no confirma un ataque. Los registros WARNING y CRITICAL duplicados se consolidan.")


def incident_table(df, masked, source):
    st.markdown("### Investigación de alertas")
    if df.empty:
        st.info("No existen alertas en este origen de datos.")
        return
    df = df.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df = df.dropna(subset=["timestamp"]).sort_values("timestamp", ascending=False)
    f1, f2, f3 = st.columns([1, 1.3, 1])
    with f1:
        severity = st.selectbox("Nivel", ["Todos", "CRITICAL", "WARNING"], key="level_filter")
    with f2:
        rule = st.selectbox("Detección", ["Todos"] + sorted(df["rule"].unique().tolist()), key="rule_filter")
    with f3:
        window = st.selectbox("Período", ["Todos", "15 minutos", "1 hora", "24 horas"], key="time_filter")
    if severity != "Todos":
        df = df.loc[df["severity"] == severity]
    if rule != "Todos":
        df = df.loc[df["rule"] == rule]
    durations = {"15 minutos": 15, "1 hora": 60, "24 horas": 1440}
    if window in durations:
        df = df.loc[df["timestamp"] >= pd.Timestamp.now() - pd.Timedelta(minutes=durations[window])]
    if masked:
        df["source_ip"] = df["source_ip"].map(mask_ip)
        df["destination_ip"] = df["destination_ip"].map(mask_ip)
    st.caption(f"{len(df):,} eventos según los filtros · máximo 16.000 líneas recientes del archivo en modo real")
    st.dataframe(df[FIELDS].head(500), hide_index=True, use_container_width=True,
                 column_config={
                     "timestamp": st.column_config.DatetimeColumn("Fecha / hora", format="DD/MM/YYYY HH:mm:ss"),
                     "severity": "Nivel", "rule": "Regla", "method": "Método",
                     "source_ip": "IP origen", "destination_ip": "IP destino",
                     "confidence": st.column_config.NumberColumn("Indicador", format="%.3f"),
                     "score": st.column_config.NumberColumn("Puntuación ML", format="%.4f"),
                 })
    st.download_button("⬇️ Exportar CSV filtrado", data=df[FIELDS].to_csv(index=False).encode("utf-8-sig"),
                       file_name="sentinel_demo.csv" if source == "Demostración" else "sentinel_alertas.csv",
                       mime="text/csv", key="export_alerts")
    st.caption("Las IP también se enmascaran en el CSV cuando el interruptor de privacidad está activado. El 'indicador' del tutorial NO representa una probabilidad de ataque.")


def ml_lab():
    st.markdown("### Laboratorio · IsolationForest")
    st.info("🧪 Experimento con datos sintéticos y modelo independiente: NO entrena ni modifica el IDS que captura paquetes.")
    st.markdown("Cambia los parámetros y observa cómo varía la clasificación. Esta sección recrea el experimento educativo que hiciste con 200 muestras.")
    c1, c2, c3 = st.columns(3)
    with c1:
        contamination = st.select_slider("Contamination", options=[0.01, 0.05, 0.1, 0.2], value=0.1)
    with c2:
        size = st.slider("Tamaño del paquete (bytes)", min_value=30, max_value=1500, value=520, step=10)
    with c3:
        rate = st.slider("Paquetes por segundo", min_value=1, max_value=300, value=12)

    result = run_experiment(contamination=contamination, size=size, rate=rate)
    a, b, c, d = st.columns(4)
    a.metric("Entrenamiento", "200 muestras")
    b.metric("Normales reconocidos", f"{result['normal_correct']}/30")
    c.metric("Anomalías reconocidas", f"{result['anomalies_correct']}/5")
    d.metric("Falsos positivos", str(result["false_positives"]))

    left, right = st.columns([1.45, 1], gap="large")
    with left:
        fig = go.Figure()
        fig.add_trace(go.Histogram(x=result["normal_scores"], name="Normales simulados", marker_color=CYAN, opacity=.72))
        fig.add_trace(go.Histogram(x=result["anomaly_scores"], name="Atípicos simulados", marker_color=RED, opacity=.7))
        fig.add_vline(x=result["threshold"], line_color=GREEN, line_dash="dash",
                      annotation_text="Umbral predict()", annotation_position="top left")
        fig.add_vline(x=-0.5, line_color=AMBER, line_dash="dot",
                      annotation_text="Umbral tutorial", annotation_position="bottom right")
        fig.update_layout(title="Distribución de puntuaciones", barmode="overlay", xaxis_title="score_samples()", yaxis_title="Muestras")
        st.plotly_chart(plot_style(fig, 345, True), use_container_width=True)
    with right:
        st.markdown("#### Tu muestra")
        st.metric("Puntuación de anomalía", f"{result['sample_score']:.4f}")
        st.metric("Predicción de Scikit-learn", "ANOMALÍA" if result["prediction"] == -1 else "NORMAL")
        st.metric("Regla del tutorial (score < -0.5)", "ACTIVADA" if result["tutorial_rule_fires"] else "NO ACTIVADA")
        st.caption(f"Bytes/segundo simulados: {size * rate:,}. El umbral aprendido de predict() es {result['threshold']:.4f}.")
    st.markdown('''<div class="note">Una puntuación más baja indica mayor rareza. <b>contamination</b> cambia el umbral usado por <code>predict()</code>, pero el código del tutorial evalúa por separado <code>score_samples() &lt; -0.5</code>. Esto no mide precisión en una red real.</div>''', unsafe_allow_html=True)


st.markdown('''
<div class="hero">
  <div class="kicker">SECURITY OPERATIONS · PYTHON · EDUCATIONAL PROJECT</div>
  <h1>🛡️ Sentinel IDS <span style="color:#55c7ff">/ v2</span></h1>
  <p>Monitor de paquetes TCP/IP · Analítica de alertas · Laboratorio de anomalías</p>
  <span class="tag">SCAPY</span> <span class="tag">ISOLATION FOREST</span> <span class="tag">STREAMLIT</span>
</div>
''', unsafe_allow_html=True)

with st.sidebar:
    st.markdown("## ⚙️ Sentinel Control")
    source = st.radio("Origen de los datos", ["Registros reales", "Demostración"],
                      index=0 if LOG_PATH.exists() else 1)
    masked = st.toggle("Proteger direcciones IP", value=True)
    section = st.radio("Sección", ["Resumen SOC", "Investigación", "Laboratorio ML"])
    st.divider()
    st.markdown("**Estado de la integración**")
    st.caption("Actualización de monitoreo y alertas cada 3 s. El laboratorio es independiente.")
    st.caption("Para telemetría real, inicia sentinel_live.py desde PowerShell como administrador; no ejecutes ids.py en paralelo.")
    st.caption("Las alertas históricas no prueban que la captura esté activa. Nunca publiques IP reales en demostraciones.")


@st.fragment(run_every="3s")
def update_live(section, source, masked):
    state, telemetry = get_status(source)
    render_status(source, state, telemetry)
    df = get_alert_data(source)
    if section == "Resumen SOC":
        traffic_view(telemetry, state)
        alert_charts(df, masked)
    else:
        incident_table(df, masked, source)


if section == "Laboratorio ML":
    ml_lab()
else:
    update_live(section, source, masked)

st.markdown("---")
st.caption("Sentinel IDS v2 · Prototipo educativo basado en un tutorial de freeCodeCamp · Las detecciones no equivalen a incidentes confirmados.")
