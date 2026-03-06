// static/topology.js

// static/topology.js

function renderTopology(topologyData) {
  if (!topologyData || !topologyData.aps) return;

  const iconBase = "/static/icons/";

  const nodes = [];
  const edges = [];

  // Helper: pretty band text
  function prettyBand(band) {
    if (!band) return "";
    const b = String(band).toLowerCase();
    if (b === "5g" || b.indexOf("5") !== -1) return "5 GHz";
    return "2.4 GHz";
  }

  // Helper: human label for security mode
  function prettySecurity(sec) {
    if (!sec) return "";
    const s = String(sec).toLowerCase();
    if (s === "open") return "Open (no encryption)";
    if (s === "wpa2-psk") return "WPA2-Personal (PSK)";
    if (s === "wpa3-sae") return "WPA3-Personal (SAE)";
    if (s === "wpa2-enterprise") return "WPA2-Enterprise";
    if (s === "wpa3-enterprise") return "WPA3-Enterprise";
    return sec;
  }

  let radiusAdded = false;

  topologyData.aps.forEach((ap) => {
    const secText = prettySecurity(ap.security_mode);
    const bandText = prettyBand(ap.band);

    // AP tooltip as plain text with newlines
    const apTitleLines = [
      `Access Point: ${ap.id}`,
      `SSID: ${ap.ssid}`,
      `Band: ${bandText}`,
      `Channel: ${ap.channel}`,
      `Security: ${secText}`,
    ];

    nodes.push({
      id: ap.id,
      label: ap.ssid,
      shape: "image",
      image: iconBase + "ap.png",
      size: 50,
      font: { size: 14, color: "#333" },
      title: apTitleLines.join("\n"),
    });

    // STAs
    ap.stas.forEach((sta) => {
      const staTitleLines = [
        `Station: ${sta}`,
        `Connected to: ${ap.ssid} (${ap.id})`,
        `Security: ${secText}`,
        `Band: ${bandText}`,
        `Channel: ${ap.channel}`,
      ];

      nodes.push({
        id: sta,
        label: sta,
        shape: "image",
        image: iconBase + "sta.png",
        size: 40,
        font: { size: 12, color: "#555" },
        title: staTitleLines.join("\n"),
      });

      edges.push({ from: sta, to: ap.id });
    });

    // RADIUS node (once) if any AP has radius
    if (ap.radius) {
      const radiusId = "radius";
      if (!radiusAdded) {
        radiusAdded = true;
        const r = ap.radius;
        const rTitleLines = [
          "RADIUS Server",
          `Address: ${r.addr || "127.0.0.1"}`,
          `Port: ${r.port || 1812}`,
        ];

        nodes.push({
          id: radiusId,
          label: "RADIUS",
          shape: "image",
          image: iconBase + "radius.png",
          size: 45,
          font: { size: 13, color: "#333" },
          title: rTitleLines.join("\n"),
        });
      }
      edges.push({ from: ap.id, to: radiusId });
    }
  });

  const container = document.getElementById("network");
  const data = {
    nodes: new vis.DataSet(nodes),
    edges: new vis.DataSet(edges),
  };

  const options = {
    layout: {
      hierarchical: {
        enabled: false,
      },
    },
    nodes: {
      borderWidth: 0,
      shadow: true,
    },
    edges: {
      color: { color: "#aaa" },
      smooth: { type: "continuous" },
      width: 1.5,
    },
    physics: {
      stabilization: true,
      barnesHut: {
        gravitationalConstant: -2500,
        centralGravity: 0.4,
        springLength: 140,
        springConstant: 0.05,
      },
    },
    interaction: {
      dragNodes: true,
      zoomView: true,
      hover: true,
      tooltipDelay: 80,
    },
  };

  new vis.Network(container, data, options);
}


/**
 * Very small HTML escaper so SSIDs etc. don't break the tooltip HTML.
 * (Local lab, so we keep it simple.)
 */
function escapeHtml(str) {
  if (str == null) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

