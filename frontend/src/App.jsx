import { useState } from "react";

function App() {
  const [evidence, setEvidence] = useState("");
  const [analysis, setAnalysis] = useState("");
  const [iocs, setIocs] = useState([]);
  const [timeline, setTimeline] = useState([]);
  const [severity, setSeverity] = useState("LOW");
  const [loading, setLoading] = useState(false);
  const [file, setFile] = useState(null);

  // =========================
  // IOC CLASSIFICATION
  // =========================
  const classifyIOC = (ioc) => {
    if (/^\d+\.\d+\.\d+\.\d+$/.test(ioc)) {
      if (
        ioc.startsWith("192.168") ||
        ioc.startsWith("10.") ||
        ioc.startsWith("172.")
      ) {
        return "Internal IP";
      }
      return "External IP";
    }

    if (ioc.endsWith(".exe")) return "Executable";

    if (ioc.match(/\.(pdf|docx|csv|txt)$/)) return "Document";

    if (/^[A-Fa-f0-9]{32,64}$/.test(ioc)) return "Hash";

    return "Unknown";
  };

  // =========================
  // IOC EXTRACTION
  // =========================
  const extractIOCs = (text = "") => {
    if (typeof text !== "string") return;

    const ipRegex = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
    const hashRegex = /\b[A-Fa-f0-9]{32,64}\b/g;
    const domainRegex = /\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b/g;
    const fileRegex = /\b[\w,\s-]+\.(txt|pdf|docx|csv|json|exe|zip)\b/g;

    const ips = text.match(ipRegex) || [];
    const hashes = text.match(hashRegex) || [];
    const domains = text.match(domainRegex) || [];
    const files = text.match(fileRegex) || [];

    setIocs([...new Set([...ips, ...hashes, ...domains, ...files])]);
  };

  // =========================
  // TIMELINE EXTRACTION
  // =========================
  const extractTimeline = (text = "") => {
    if (typeof text !== "string") return;

    const lines = text.split("\n");
    const events = [];

    lines.forEach((line) => {
      if (
        line.toLowerCase().includes("login") ||
        line.toLowerCase().includes("failed") ||
        line.toLowerCase().includes("attack") ||
        line.toLowerCase().includes("traffic") ||
        line.toLowerCase().includes("malware") ||
        line.toLowerCase().includes("access")
      ) {
        events.push(line);
      }
    });

    setTimeline(events);
  };

  // =========================
  // ANALYZE EVIDENCE
  // =========================
  const analyzeEvidence = async () => {
    setLoading(true);

    try {
      const formData = new FormData();
      formData.append("evidence", evidence);

      if (file) formData.append("file", file);

      // ✅ FIXED URL (IMPORTANT)
      const response = await fetch(
        "https://forensiai-backend.onrender.com/analyze",
        {
          method: "POST",
          body: formData,
        }
      );

      const text = await response.text();

      let data;
      try {
        data = JSON.parse(text);
      } catch {
        throw new Error("Invalid JSON response from backend");
      }

      if (!response.ok) {
        throw new Error(data?.detail || "Server error");
      }

      const result =
        typeof data.analysis === "string" ? data.analysis : "";

      setAnalysis(result);

      if (result) {
        extractIOCs(result);
        extractTimeline(result);

        // =========================
        // SEVERITY ENGINE
        // =========================
        const lower = result.toLowerCase();

        if (
          lower.includes("malware") ||
          lower.includes("privilege escalation") ||
          lower.includes("data exfiltration")
        ) {
          setSeverity("CRITICAL");
        } else if (
          lower.includes("failed login") ||
          lower.includes("brute force")
        ) {
          setSeverity("HIGH");
        } else {
          setSeverity("MEDIUM");
        }
      }
    } catch (error) {
      console.error("Analysis error:", error);
      setAnalysis("Error analyzing evidence.");
    }

    setLoading(false);
  };

  const ipCount = iocs.filter((ioc) =>
    /^\d+\.\d+\.\d+\.\d+$/.test(ioc)
  ).length;

  return (
    <div className="min-h-screen bg-slate-950 text-white p-8">
      <div className="max-w-6xl mx-auto">

        {/* HEADER */}
        <div className="mb-10">
          <h1 className="text-5xl font-bold text-cyan-400 mb-3">
            ForensiAI
          </h1>
          <p className="text-slate-400 text-lg">
            Autonomous Cybercrime Evidence Investigation Agent
          </p>
        </div>

        {/* INPUT */}
        <div className="bg-slate-900 border border-cyan-500/20 rounded-2xl p-6">
          <input
            type="file"
            accept=".txt,.log,.json,.csv,.pdf"
            onChange={(e) => setFile(e.target.files[0])}
            className="mb-4 w-full text-sm text-slate-300"
          />

          <textarea
            rows="10"
            value={evidence}
            onChange={(e) => setEvidence(e.target.value)}
            placeholder="Paste evidence..."
            className="w-full bg-slate-950 p-4 rounded-xl border border-slate-700"
          />

          <button
            onClick={analyzeEvidence}
            className="mt-6 bg-cyan-500 px-8 py-3 rounded-xl text-black font-bold"
          >
            {loading ? "Analyzing..." : "Analyze Evidence"}
          </button>
        </div>

        {/* RESULTS */}
        {analysis && (
          <div className="mt-10 space-y-6">

            {/* STATS */}
            <div className="grid grid-cols-4 gap-4">
              <div className="bg-slate-900 p-4 rounded-xl">
                Threat: {severity}
              </div>
              <div className="bg-slate-900 p-4 rounded-xl">
                IOCs: {iocs.length}
              </div>
              <div className="bg-slate-900 p-4 rounded-xl">
                IPs: {ipCount}
              </div>
              <div className="bg-slate-900 p-4 rounded-xl">
                Timeline: {timeline.length}
              </div>
            </div>

            {/* TIMELINE */}
            <div className="bg-slate-900 p-6 rounded-xl">
              <h2 className="text-cyan-400 text-xl mb-4">
                Timeline
              </h2>
              {timeline.map((t, i) => (
                <p key={i} className="text-slate-300 mb-2">
                  • {t}
                </p>
              ))}
            </div>

            {/* IOCs */}
            <div className="bg-slate-900 p-6 rounded-xl">
              <h2 className="text-red-400 text-xl mb-4">
                IOCs
              </h2>
              {iocs.map((ioc, i) => (
                <div key={i} className="mb-2">
                  {ioc} — {classifyIOC(ioc)}
                </div>
              ))}
            </div>

            {/* REPORT */}
            <div className="bg-slate-900 p-6 rounded-xl">
              <h2 className="text-cyan-400 text-xl mb-4">
                Report
              </h2>
              <pre className="whitespace-pre-wrap text-slate-300">
                {analysis}
              </pre>
            </div>

          </div>
        )}

      </div>
    </div>
  );
}

export default App;