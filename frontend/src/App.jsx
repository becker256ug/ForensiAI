import { useState } from "react";

import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Legend,
} from "recharts";

function App() {

  const [evidence, setEvidence] = useState("");
  const [analysis, setAnalysis] = useState("");
  const [iocs, setIocs] = useState([]);
  const [timeline, setTimeline] = useState([]);
  const [ipChartData, setIpChartData] = useState([]);
  const [attackChartData, setAttackChartData] = useState([]);
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

    if (ioc.endsWith(".exe")) {
      return "Executable";
    }

    if (
      ioc.endsWith(".pdf") ||
      ioc.endsWith(".docx") ||
      ioc.endsWith(".csv") ||
      ioc.endsWith(".txt")
    ) {
      return "Document";
    }

    if (/^[A-Fa-f0-9]{32,64}$/.test(ioc)) {
      return "Hash";
    }

    return "Unknown";
  };

  // =========================
  // IOC EXTRACTION
  // =========================

  const extractIOCs = (text) => {

    const ipRegex =
      /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;

    const hashRegex =
      /\b[A-Fa-f0-9]{32,64}\b/g;

    const domainRegex =
      /\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b/g;

    const fileRegex =
      /\b[\w,\s-]+\.(txt|pdf|docx|csv|json|exe|zip)\b/g;

    const ips = text.match(ipRegex) || [];
    const hashes = text.match(hashRegex) || [];
    const domains = text.match(domainRegex) || [];
    const files = text.match(fileRegex) || [];

    const combined = [
      ...new Set([
        ...ips,
        ...hashes,
        ...domains,
        ...files
      ])
    ];

    setIocs(combined);
  };

  // =========================
  // TIMELINE EXTRACTION
  // =========================

  const extractTimeline = (text) => {

    const lines = text.split("\n");

    const timelineEvents = [];

    lines.forEach((line) => {

      const lower = line.toLowerCase();

      if (
        lower.includes("login") ||
        lower.includes("failed") ||
        lower.includes("attack") ||
        lower.includes("traffic") ||
        lower.includes("malware") ||
        lower.includes("access")
      ) {
        timelineEvents.push(line);
      }

    });

    setTimeline(timelineEvents);
  };

  // =========================
  // IP CHART
  // =========================

  const generateIPChart = (text) => {

    const ipRegex =
      /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;

    const ips = text.match(ipRegex) || [];

    const frequency = {};

    ips.forEach((ip) => {

      frequency[ip] =
        (frequency[ip] || 0) + 1;

    });

    const chartData = Object.keys(frequency)
      .map((ip) => ({
        ip,
        count: frequency[ip],
      }))
      .slice(0, 10);

    setIpChartData(chartData);
  };

  // =========================
  // ATTACK CHART
  // =========================

  const generateAttackChart = (text) => {

    const categories = [
      "Brute_Force",
      "DDoS_Attempt",
      "Malware",
      "Phishing",
      "Unauthorized_Access",
      "Suspicious",
    ];

    const results = [];

    categories.forEach((category) => {

      const regex =
        new RegExp(category, "gi");

      const matches =
        text.match(regex);

      results.push({
        name: category,
        value: matches ? matches.length : 0,
      });

    });

    setAttackChartData(results);
  };

  // =========================
  // ANALYZE EVIDENCE
  // =========================

  const analyzeEvidence = async () => {

    setLoading(true);

    try {

      const formData = new FormData();

      formData.append("evidence", evidence);

      if (file) {
        formData.append("file", file);
      }

      const response = await fetch(
        "https://forensiai-backend.onrender.com/analyze",
        {
          method: "POST",
          body: formData,
        }
      );

      const data = await response.json();

      const result =
        typeof data.analysis === "string"
          ? data.analysis
          : "";

      setAnalysis(result);

      if (result) {

        extractIOCs(result);

        extractTimeline(result);

        generateIPChart(result);

        generateAttackChart(result);

        // =========================
        // SEVERITY ENGINE
        // =========================

        const lower =
          result.toLowerCase();

        if (
          lower.includes("malware") ||
          lower.includes("privilege escalation") ||
          lower.includes("data exfiltration")
        ) {
          setSeverity("CRITICAL");
        }

        else if (
          lower.includes("failed login") ||
          lower.includes("brute force")
        ) {
          setSeverity("HIGH");
        }

        else {
          setSeverity("MEDIUM");
        }

      }

    } catch (error) {

      console.error(error);

      setAnalysis("Error analyzing evidence.");

    }

    setLoading(false);
  };

  // =========================
  // STATISTICS
  // =========================

  const ipCount = iocs.filter(
    (ioc) =>
      /^\d+\.\d+\.\d+\.\d+$/.test(ioc)
  ).length;

  return (

    <div className="min-h-screen bg-slate-950 text-white p-8">

      <div className="max-w-7xl mx-auto">

        {/* HEADER */}

        <div className="mb-10">

          <h1 className="text-5xl font-bold text-cyan-400 mb-3">
            ForensiAI
          </h1>

          <p className="text-slate-400 text-lg">
            Autonomous Cybercrime Evidence Investigation Agent
          </p>

        </div>

        {/* EVIDENCE INPUT */}

        <div className="bg-slate-900 border border-cyan-500/20 rounded-2xl p-6 shadow-2xl">

          <h2 className="text-2xl font-semibold mb-4 text-cyan-300">
            Submit Digital Evidence
          </h2>

          <input
            type="file"
            accept=".txt,.log,.json,.csv,.pdf"
            onChange={(e) => setFile(e.target.files[0])}
            className="mb-4 block w-full text-sm text-slate-300"
          />

          <textarea
            rows="10"
            value={evidence}
            onChange={(e) => setEvidence(e.target.value)}
            placeholder="Paste logs, CSV data, alerts, malware traces, firewall evidence, or suspicious activity..."
            className="w-full bg-slate-950 border border-slate-700 rounded-xl p-4 text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
          />

          <div className="flex gap-4 mt-6">

            <button
              onClick={analyzeEvidence}
              className="bg-cyan-500 hover:bg-cyan-400 text-black font-bold px-8 py-4 rounded-xl transition-all"
            >
              {loading ? "Analyzing..." : "Analyze Evidence"}
            </button>

            <button
              onClick={() => {

                const blob = new Blob(
                  [analysis],
                  { type: "text/plain" }
                );

                const url =
                  window.URL.createObjectURL(blob);

                const a =
                  document.createElement("a");

                a.href = url;

                a.download =
                  "ForensiAI_Report.txt";

                a.click();
              }}
              className="bg-green-500 hover:bg-green-400 text-black font-bold px-8 py-4 rounded-xl transition-all"
            >
              Export Report
            </button>

          </div>

        </div>

        {/* RESULTS */}

        {analysis && (

          <div className="mt-10 space-y-6">

            {/* DASHBOARD */}

            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">

              <div className="bg-slate-900 p-5 rounded-2xl border border-red-500/20">

                <p className="text-slate-400 text-sm">
                  Threat Level
                </p>

                <h3 className="text-3xl font-bold text-red-400">
                  {severity}
                </h3>

              </div>

              <div className="bg-slate-900 p-5 rounded-2xl border border-cyan-500/20">

                <p className="text-slate-400 text-sm">
                  Total IOCs
                </p>

                <h3 className="text-3xl font-bold text-cyan-400">
                  {iocs.length}
                </h3>

              </div>

              <div className="bg-slate-900 p-5 rounded-2xl border border-yellow-500/20">

                <p className="text-slate-400 text-sm">
                  IP Addresses
                </p>

                <h3 className="text-3xl font-bold text-yellow-300">
                  {ipCount}
                </h3>

              </div>

              <div className="bg-slate-900 p-5 rounded-2xl border border-green-500/20">

                <p className="text-slate-400 text-sm">
                  Timeline Events
                </p>

                <h3 className="text-3xl font-bold text-green-400">
                  {timeline.length}
                </h3>

              </div>

            </div>

            {/* CHARTS */}

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">

              {/* BAR CHART */}

              <div className="bg-slate-900 border border-cyan-500/20 rounded-2xl p-6">

                <h2 className="text-2xl font-bold text-cyan-400 mb-6">
                  Suspicious IP Frequency
                </h2>

                <ResponsiveContainer width="100%" height={300}>

                  <BarChart data={ipChartData}>

                    <XAxis dataKey="ip" />
                    <YAxis />
                    <Tooltip />

                    <Bar
                      dataKey="count"
                      fill="#06b6d4"
                    />

                  </BarChart>

                </ResponsiveContainer>

              </div>

              {/* PIE CHART */}

              <div className="bg-slate-900 border border-red-500/20 rounded-2xl p-6">

                <h2 className="text-2xl font-bold text-red-400 mb-6">
                  Attack Categories
                </h2>

                <ResponsiveContainer width="100%" height={300}>

                  <PieChart>

                    <Pie
                      data={attackChartData}
                      dataKey="value"
                      nameKey="name"
                      outerRadius={100}
                      label
                    >

                      {attackChartData.map((entry, index) => (

                        <Cell
                          key={index}
                          fill={
                            [
                              "#06b6d4",
                              "#ef4444",
                              "#eab308",
                              "#22c55e",
                              "#8b5cf6",
                              "#f97316",
                            ][index % 6]
                          }
                        />

                      ))}

                    </Pie>

                    <Tooltip />

                    <Legend />

                  </PieChart>

                </ResponsiveContainer>

              </div>

            </div>

            {/* TIMELINE */}

            <div className="bg-slate-900 border border-cyan-500/20 rounded-2xl p-6">

              <h2 className="text-2xl font-bold text-cyan-400 mb-6">
                Attack Timeline Reconstruction
              </h2>

              <div className="space-y-4">

                {timeline.map((event, index) => (

                  <div
                    key={index}
                    className="flex items-start gap-4"
                  >

                    <div className="w-4 h-4 mt-2 rounded-full bg-cyan-400"></div>

                    <div className="bg-slate-950 border border-slate-700 rounded-xl p-4 w-full text-slate-300">
                      {event}
                    </div>

                  </div>

                ))}

              </div>

            </div>

            {/* IOC PANEL */}

            <div className="bg-slate-900 border border-red-500/20 rounded-2xl p-6">

              <h2 className="text-2xl font-bold text-red-400 mb-4">
                Indicators of Compromise (IOCs)
              </h2>

              {iocs.length === 0 ? (

                <p className="text-slate-400">
                  No IOCs detected.
                </p>

              ) : (

                <div className="flex flex-wrap gap-3">

                  {iocs.map((ioc, index) => (

                    <div
                      key={index}
                      className="bg-slate-950 border border-red-500/30 px-4 py-3 rounded-xl text-red-300 text-sm"
                    >

                      <p className="font-bold">
                        {ioc}
                      </p>

                      <p className="text-xs text-slate-400 mt-1">
                        {classifyIOC(ioc)}
                      </p>

                    </div>

                  ))}

                </div>

              )}

            </div>

            {/* REPORT */}

            <div className="bg-slate-900 border border-cyan-500/20 rounded-2xl p-6 shadow-2xl">

              <h2 className="text-3xl font-bold mb-6 text-cyan-400">
                Investigation Report
              </h2>

              <div className="whitespace-pre-wrap text-slate-300 leading-8 overflow-auto max-h-[700px]">
                {analysis}
              </div>

            </div>

          </div>

        )}

      </div>

    </div>

  );
}

export default App;