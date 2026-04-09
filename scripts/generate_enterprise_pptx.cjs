#!/usr/bin/env node

const path = require("node:path");

const ROOT = process.env.ASCOPE_ROOT || path.resolve(__dirname, "..");

function loadPptxGenJS() {
  const candidates = [
    process.env.PPTXGENJS_PATH,
    "pptxgenjs",
    path.join(ROOT, "node_modules", "pptxgenjs"),
  ].filter(Boolean);

  for (const candidate of candidates) {
    try {
      return require(candidate);
    } catch (error) {
      if (error.code !== "MODULE_NOT_FOUND") {
        throw error;
      }
    }
  }

  throw new Error(
    "Unable to load pptxgenjs. Install it locally or set PPTXGENJS_PATH to your local module path.",
  );
}

const PptxGenJS = loadPptxGenJS();

const pptx = new PptxGenJS();
pptx.layout = "LAYOUT_WIDE";
pptx.author = "OpenScope";
pptx.company = "OpenScope";
pptx.subject = "Enterprise agentic workflow security";
pptx.title = "Why AI Gateways Are Not Enough";
pptx.lang = "en-US";

const COLORS = {
  navy: "0F172A",
  blue: "2563EB",
  green: "2E7D32",
  red: "C62828",
  ink: "111827",
  muted: "475569",
  line: "CBD5E1",
  soft: "F8FAFC",
};

const DIAGRAMS = path.join(ROOT, "docs", "diagrams");

function addFrame(slide, title, subtitle) {
  slide.background = { color: "FFFFFF" };
  slide.addShape(pptx.ShapeType.rect, {
    x: 0,
    y: 0,
    w: 13.333,
    h: 0.55,
    fill: { color: COLORS.navy },
    line: { color: COLORS.navy },
  });
  slide.addText(title, {
    x: 0.55,
    y: 0.38,
    w: 8.9,
    h: 0.45,
    fontFace: "Aptos Display",
    fontSize: 24,
    bold: true,
    color: COLORS.ink,
    margin: 0,
  });
  if (subtitle) {
    slide.addText(subtitle, {
      x: 0.58,
      y: 0.9,
      w: 10.6,
      h: 0.3,
      fontFace: "Aptos",
      fontSize: 10,
      color: COLORS.muted,
      margin: 0,
    });
  }
}

function addBullets(slide, items, opts = {}) {
  const x = opts.x ?? 0.8;
  const y = opts.y ?? 1.5;
  const w = opts.w ?? 5.2;
  const h = opts.h ?? 4.8;
  const fontSize = opts.fontSize ?? 19;

  const runs = [];
  items.forEach((text) => {
    runs.push({
      text,
      options: {
        bullet: { indent: 16 },
        breakLine: true,
      },
    });
  });

  slide.addText(runs, {
    x,
    y,
    w,
    h,
    fontFace: "Aptos",
    fontSize,
    color: COLORS.ink,
    paraSpaceAfterPt: 10,
    valign: "top",
    margin: 0,
  });
}

function addKeyPoint(slide, text) {
  slide.addShape(pptx.ShapeType.roundRect, {
    x: 0.78,
    y: 6.45,
    w: 11.8,
    h: 0.55,
    rectRadius: 0.06,
    fill: { color: "EEF6FF" },
    line: { color: "B6D4FE", width: 1 },
  });
  slide.addText(`Key point: ${text}`, {
    x: 0.96,
    y: 6.58,
    w: 11.3,
    h: 0.22,
    fontFace: "Aptos",
    fontSize: 14,
    color: COLORS.blue,
    bold: true,
    margin: 0,
  });
}

function addDiagram(slide, file, opts = {}) {
  slide.addImage({
    path: path.join(DIAGRAMS, file),
    x: opts.x ?? 6.5,
    y: opts.y ?? 1.35,
    w: opts.w ?? 6.0,
    h: opts.h ?? 4.7,
  });
}

// Slide 1
{
  const slide = pptx.addSlide();
  slide.background = { color: "FFFFFF" };
  slide.addShape(pptx.ShapeType.rect, {
    x: 0,
    y: 0,
    w: 13.333,
    h: 7.5,
    fill: { color: COLORS.navy },
    line: { color: COLORS.navy },
  });
  slide.addText("Why AI Gateways Are Not Enough", {
    x: 0.8,
    y: 1.15,
    w: 9.8,
    h: 0.8,
    fontFace: "Aptos Display",
    fontSize: 28,
    bold: true,
    color: "FFFFFF",
    margin: 0,
  });
  slide.addText("High-risk agentic workflows need execution containment", {
    x: 0.82,
    y: 2.0,
    w: 8.5,
    h: 0.4,
    fontFace: "Aptos",
    fontSize: 16,
    color: "DCE7F7",
    margin: 0,
  });
  addBullets(
    slide,
    [
      "AI gateways are valuable",
      "They solve real governance problems",
      "But high-risk agentic workflows need more than traffic inspection",
      "They need a stronger execution boundary",
    ],
    { x: 0.95, y: 3.0, w: 7.6, h: 2.8, fontSize: 20 }
  );
}

// Slide 2
{
  const slide = pptx.addSlide();
  addFrame(slide, "AI Gateways Solve a Real Problem", "Tailscale Apture is one example of this category");
  addBullets(slide, [
    "Centralized control across many agents and tools",
    "Model and provider routing",
    "Org-wide policy and visibility",
    "Session logging and review",
    "Fast additive rollout",
  ]);
  addKeyPoint(slide, "AI gateways are a sensible first step for broad AI governance.");
}

// Slide 3
{
  const slide = pptx.addSlide();
  addFrame(slide, "The Core Security Difference");
  addDiagram(slide, "filter_vs_scope.png", { x: 0.9, y: 1.45, w: 11.5, h: 4.7 });
  addKeyPoint(slide, "A gateway inspects a raw privileged path. A brokered-capability model removes that raw path from the agent.");
}

// Slide 4
{
  const slide = pptx.addSlide();
  addFrame(slide, "The Key Management Difference");
  addDiagram(slide, "where_the_key_lives.png", { x: 0.95, y: 1.45, w: 11.4, h: 4.7 });
  addKeyPoint(slide, "For high-risk systems, the stronger requirement is that the agent never possesses the key or broad permission at all.");
}

// Slide 5
{
  const slide = pptx.addSlide();
  addFrame(slide, "New Risk in Agentic Workflows", "Behavior can change without a traditional redeploy");
  addBullets(slide, [
    "Traditional enterprise tools change by release and deployment",
    "Agentic systems can change through prompt updates",
    "They can change through tool config changes",
    "They can change through SKILL.md updates",
    "They can change through runtime instruction changes",
  ], { x: 0.9, y: 1.6, w: 10.9, h: 3.8, fontSize: 19 });
  addKeyPoint(slide, "Security can no longer rely only on slow application change cycles.");
}

// Slide 6
{
  const slide = pptx.addSlide();
  addFrame(slide, "Second New Risk in Agentic Workflows", "Agents can probe for alternate paths faster than humans");
  addDiagram(slide, "why_bypass_happens.png", { x: 0.95, y: 1.45, w: 11.3, h: 4.6 });
  addKeyPoint(slide, "A gateway often protects a path, while a capable agent searches for any path that completes the task.");
}

// Slide 7
{
  const slide = pptx.addSlide();
  addFrame(slide, "When Capability Brokering Becomes Necessary");
  addBullets(slide, [
    "Production operations",
    "SSH-based remediation",
    "Sensitive databases",
    "Internal admin APIs",
    "Endpoint automation",
    "Finance, support, or customer-impacting actions",
  ], { x: 0.95, y: 1.55, w: 7.4, h: 4.4, fontSize: 20 });
  slide.addShape(pptx.ShapeType.roundRect, {
    x: 8.65,
    y: 1.8,
    w: 3.7,
    h: 2.25,
    rectRadius: 0.06,
    fill: { color: "F8FAFC" },
    line: { color: COLORS.line, width: 1 },
  });
  slide.addText("Best fit when:\nThe system owner does not want the agent to ever hold the raw primitive.", {
    x: 8.95,
    y: 2.1,
    w: 3.1,
    h: 1.5,
    fontFace: "Aptos",
    fontSize: 18,
    bold: true,
    color: COLORS.ink,
    valign: "mid",
    margin: 0,
  });
  addKeyPoint(slide, "Brokered capabilities are most valuable when execution must stay tightly bounded.");
}

// Slide 8
{
  const slide = pptx.addSlide();
  addFrame(slide, "Recommended Architecture");
  addDiagram(slide, "architecture_difference.png", { x: 0.95, y: 1.45, w: 11.3, h: 4.35 });
  addKeyPoint(slide, "Use an AI gateway for traffic-plane governance and a brokered-capability layer for execution-plane containment.");
}

// Slide 9
{
  const slide = pptx.addSlide();
  addFrame(slide, "The Decision Question");
  slide.addText("Instead of asking:", {
    x: 0.95,
    y: 1.7,
    w: 3.5,
    h: 0.35,
    fontFace: "Aptos Display",
    fontSize: 24,
    bold: true,
    color: COLORS.red,
    margin: 0,
  });
  slide.addText("Can this product apply policy to tools?", {
    x: 1.0,
    y: 2.3,
    w: 5.2,
    h: 0.5,
    fontFace: "Aptos",
    fontSize: 24,
    italic: true,
    color: COLORS.ink,
    margin: 0,
  });
  slide.addText("Ask:", {
    x: 0.95,
    y: 3.45,
    w: 2.0,
    h: 0.35,
    fontFace: "Aptos Display",
    fontSize: 24,
    bold: true,
    color: COLORS.green,
    margin: 0,
  });
  slide.addText("Does this product leave the raw privileged primitive exposed to the agent?", {
    x: 1.0,
    y: 4.05,
    w: 9.8,
    h: 0.8,
    fontFace: "Aptos",
    fontSize: 26,
    bold: true,
    color: COLORS.ink,
    margin: 0,
  });
  addKeyPoint(slide, "High-risk agentic workflows need more than AI governance. They need containment of privileged execution.");
}

const out = process.argv[2];
if (!out) {
  console.error("usage: node generate_enterprise_pptx.cjs <output.pptx>");
  process.exit(2);
}

pptx.writeFile({ fileName: out });
