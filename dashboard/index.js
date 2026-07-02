(function () {
  "use strict";

  const SDK = window.__HERMES_PLUGIN_SDK__;
  const registry = window.__HERMES_PLUGINS__;
  if (!SDK || !registry || typeof registry.register !== "function") return;

  const React = SDK.React;
  const h = React.createElement;
  const fetchJSON = SDK.fetchJSON || ((url, options) => fetch(url, options).then((response) => {
    if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
    return response.json();
  }));
  function escapeHtml(value) {
    return String(value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");
  }

  function highlightYamlLine(line) {
    const escaped = escapeHtml(line);
    const commentIndex = escaped.indexOf("#");
    const main = commentIndex >= 0 ? escaped.slice(0, commentIndex) : escaped;
    const comment = commentIndex >= 0 ? escaped.slice(commentIndex) : "";
    let highlighted = main
      .replace(/^(\s*)(-\s+)/, "$1<span style=\"color:#f6c177;\">$2</span>")
      .replace(/^(\s*)([A-Za-z0-9_.-]+)(\s*:)/, "$1<span style=\"color:#8bd5ff;font-weight:600;\">$2</span>$3")
      .replace(/(:\s*)(true|false|null)(\s*)$/i, "$1<span style=\"color:#c4a7e7;\">$2</span>$3")
      .replace(/(:\s*)([0-9]+(?:\.[0-9]+)?)(\s*)$/, "$1<span style=\"color:#f6c177;\">$2</span>$3")
      .replace(/(:\s*)(&quot;[^&]*&quot;|'[^']*')(\s*)$/, "$1<span style=\"color:#a6e3a1;\">$2</span>$3");
    if (comment) highlighted += `<span style="color:#8b949e;">${comment}</span>`;
    return highlighted || " ";
  }

  function highlightYaml(value) {
    return String(value || "").split("\n").map(highlightYamlLine).join("\n");
  }

  function WorkRbacPage() {
    const [policy, setPolicy] = React.useState("");
    const [status, setStatus] = React.useState("Loading...");
    const [saving, setSaving] = React.useState(false);
    const highlightRef = React.useRef(null);

    React.useEffect(() => {
      let cancelled = false;
      fetchJSON("/api/plugins/work-rbac/policy")
        .then((data) => {
          if (cancelled) return;
          setPolicy(data.yaml_text || "");
          setStatus("");
        })
        .catch((error) => {
          if (!cancelled) setStatus(`Load failed: ${error.message}`);
        });
      return () => {
        cancelled = true;
      };
    }, []);

    async function savePolicy() {
      setSaving(true);
      setStatus("Saving...");
      try {
        await fetchJSON("/api/plugins/work-rbac/policy", {
          method: "PUT",
          headers: {"Content-Type": "application/json"},
          body: JSON.stringify({yaml_text: policy}),
        });
        setStatus("Saved. Restart active gateway sessions to reload plugin state if needed.");
      } catch (error) {
        setStatus(`Save failed: ${error.message}`);
      } finally {
        setSaving(false);
      }
    }

    function syncScroll(event) {
      if (highlightRef.current) {
        highlightRef.current.scrollTop = event.currentTarget.scrollTop;
        highlightRef.current.scrollLeft = event.currentTarget.scrollLeft;
      }
    }

    const editorFont = "13px/1.5 ui-monospace, SFMono-Regular, Menlo, monospace";

    return h("div", {
      style: {
        width: "100%",
        minHeight: "calc(100vh - 96px)",
        padding: "24px clamp(18px, 3vw, 40px)",
        boxSizing: "border-box",
        display: "flex",
        flexDirection: "column",
      },
    },
      h("h1", {
        style: {fontSize: "24px", margin: "0 0 12px", color: "#fff"},
      }, "Work RBAC"),
      h("p", {
        style: {color: "rgba(255,255,255,0.82)", margin: "0 0 16px"},
      }, "Owner can use all tools and paths. Guest can only use allowed_tools inside configured public directories."),
      h("div", {
        style: {
          position: "relative",
          width: "100%",
          flex: "1 1 auto",
          minHeight: "min(680px, calc(100vh - 300px))",
          border: "1px solid rgba(255,255,255,0.16)",
          borderRadius: "8px",
          background: "#05070a",
          boxShadow: "0 18px 48px rgba(0,0,0,0.28)",
          overflow: "hidden",
          boxSizing: "border-box",
        },
      },
        h("pre", {
          ref: highlightRef,
          ariaHidden: true,
          dangerouslySetInnerHTML: {__html: highlightYaml(policy)},
          style: {
            position: "absolute",
            inset: 0,
            margin: 0,
            padding: "12px",
            overflow: "hidden",
            whiteSpace: "pre",
            font: editorFont,
            color: "#d8dee9",
            pointerEvents: "none",
            tabSize: 2,
          },
        }),
        h("textarea", {
          spellCheck: false,
          value: policy,
          onChange: (event) => setPolicy(event.target.value),
          onScroll: syncScroll,
          style: {
            position: "absolute",
            inset: 0,
            width: "100%",
            height: "100%",
            margin: 0,
            padding: "12px",
            boxSizing: "border-box",
            border: "0",
            outline: "0",
            resize: "none",
            overflow: "auto",
            font: editorFont,
            color: "transparent",
            WebkitTextFillColor: "transparent",
            caretColor: "#fff",
            background: "transparent",
            whiteSpace: "pre",
            tabSize: 2,
          },
        })
      ),
      h("div", {
        style: {
          display: "flex",
          gap: "8px",
          alignItems: "center",
          marginTop: "12px",
        },
      },
        h("button", {
          type: "button",
          disabled: saving,
          onClick: savePolicy,
          style: {
            padding: "8px 12px",
            border: "1px solid #222",
            background: saving ? "#666" : "#222",
            color: "#fff",
            borderRadius: "6px",
            cursor: saving ? "default" : "pointer",
          },
        }, saving ? "Saving..." : "Save Policy"),
        h("span", {style: {color: "#666"}}, status)
      ),
      h("div", {
        style: {
          marginTop: "18px",
          paddingTop: "16px",
          borderTop: "1px solid rgba(255,255,255,0.22)",
          color: "rgba(255,255,255,0.84)",
          lineHeight: 1.55,
          maxWidth: "1120px",
        },
      },
        h("div", {
          style: {
            fontWeight: 700,
            color: "#fff",
            marginBottom: "6px",
          },
        }, "配置建议"),
        h("p", {style: {margin: "0 0 8px"}},
          "优先让 agent 根据日志和你的自然语言来改这份策略，页面更适合用来核对最终 YAML。"
        ),
        h("p", {style: {margin: "0 0 8px"}},
          "例如直接说：帮我修改 Hermes 的 Work RBAC 插件配置，把张三设为 owner；李四这类访客只能读 /path/to/shared；访客只能使用 read_file 和 search_files；访客会话总结发到我的 Feishu DM。"
        )
      )
    );
  }

  registry.register("work-rbac", WorkRbacPage);
})();
