import json
import joblib
import pandas as pd
import streamlit as st
import anthropic

st.set_page_config(page_title="كاشف هجمات IoT", page_icon="🛡️")
st.title("🛡️ كاشف هجمات شبكات IoT")

# ---------- المودل (يتحمل مرة وحدة بس) ----------
@st.cache_resource
def load_model():
    saved = joblib.load("iot_model_light.joblib")
    return saved["model"], saved["features"]

model, FEATURES = load_model()

def category(label):
    if label == "BenignTraffic": return "Benign"
    if label.startswith("DDoS"): return "DDoS"
    if label.startswith("DoS"): return "DoS"
    if label.startswith("Mirai"): return "Mirai"
    if label.startswith("Recon") or label == "VulnerabilityScan": return "Recon"
    if label in ["MITM-ArpSpoofing", "DNS_Spoofing"]: return "Spoofing"
    if label == "DictionaryBruteForce": return "BruteForce"
    return "Web"

# ---------- المفتاح من الشريط الجانبي (ما ينحفظ في الكود) ----------
api_key = st.sidebar.text_input("مفتاح Anthropic API", type="password")
MODEL_NAME = "claude-sonnet-5"

# ---------- رفع الملف ----------
uploaded = st.file_uploader("ارفع ملف ترافيك (CSV)", type="csv")

if uploaded:
    df = pd.read_csv(uploaded, nrows=20000)
    missing = [f for f in FEATURES if f not in df.columns]
    if missing:
        st.error(f"الملف ناقصه أعمدة: {missing[:5]}")
        st.stop()

    preds = model.predict(df[FEATURES])
    confidence = model.predict_proba(df[FEATURES]).max(axis=1)
    attacks = preds != "Benign"
    counts = pd.Series(preds).value_counts()

    c1, c2, c3 = st.columns(3)
    c1.metric("صفوف مفحوصة", len(df))
    c2.metric("نسبة الهجمات", f"{100 * attacks.mean():.1f}%")
    c3.metric("ثقة منخفضة", int((confidence < 0.6).sum()))
    st.bar_chart(counts)

    # ---------- أدوات الإيجنت ----------
    def scan_traffic():
        result = {
            "rows_scanned": len(df),
            "predicted_counts": counts.to_dict(),
            "attack_percentage": round(100 * attacks.mean(), 2),
            "low_confidence_rows": int((confidence < 0.6).sum()),
        }
        if "label" in df.columns:
            truth = df["label"].apply(category)
            result["missed_attacks"] = int(((truth != "Benign") & (preds == "Benign")).sum())
            result["false_alarms"] = int(((truth == "Benign") & (preds != "Benign")).sum())
        return json.dumps(result)

    def top_features(n=10):
        imp = pd.Series(model.feature_importances_, index=FEATURES).sort_values(ascending=False)
        return json.dumps(imp.head(n).round(4).to_dict())

    TOOL_FUNCS = {"scan_traffic": scan_traffic, "top_features": top_features}
    tools = [
        {"name": "scan_traffic",
         "description": "Scans the uploaded IoT traffic with the detection model. Returns attack counts per category, attack percentage, low-confidence rows, missed attacks and false alarms.",
         "input_schema": {"type": "object", "properties": {}}},
        {"name": "top_features",
         "description": "Returns the most important traffic features the detection model relies on.",
         "input_schema": {"type": "object", "properties": {"n": {"type": "integer"}}}},
    ]
    SYSTEM = """You are an IoT network security analyst. Use the tools, then write a clear,
short report in Saudi Arabic: what attacks were found, how serious, and what to do.
Be honest that the model is weak at BruteForce and Web attacks."""

    def run_agent(client, question):
        messages = [{"role": "user", "content": question}]
        while True:
            resp = client.messages.create(model=MODEL_NAME, max_tokens=2000,
                                          system=SYSTEM, tools=tools, messages=messages)
            messages.append({"role": "assistant", "content": resp.content})
            if resp.stop_reason != "tool_use":
                return "".join(b.text for b in resp.content if b.type == "text")
            results = []
            for b in resp.content:
                if b.type == "tool_use":
                    st.caption(f"🔧 الإيجنت يستخدم: {b.name}")
                    output = TOOL_FUNCS[b.name](**b.input)
                    results.append({"type": "tool_result", "tool_use_id": b.id, "content": output})
            messages.append({"role": "user", "content": results})

    # ---------- زر التقرير ----------
    question = st.text_input("اسأل الإيجنت", "حلل الترافيك وقل لي هل الشبكة تحت هجوم")
    if st.button("🤖 اطلب تقرير"):
        if not api_key:
            st.warning("حط مفتاح API في الشريط الجانبي أول")
        else:
            client = anthropic.Anthropic(api_key=api_key.strip())
            with st.spinner("الإيجنت يحلل..."):
                st.markdown(run_agent(client, question))
