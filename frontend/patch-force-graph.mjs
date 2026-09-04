import { readFileSync, writeFileSync } from 'node:fs'

const FILES = [
  'node_modules/force-graph/dist/force-graph.mjs', // module entry actually bundled by vite
  'node_modules/force-graph/dist/force-graph.js',  // cjs dist (safety)
]

const newBody = (indent, isMjs) => {
  const accessor = isMjs ? 'accessorFn' : 'index$3'
  const tx = isMjs ? 'zoomTransform' : 'transform'
  return `var obj = null;
${indent}// Geometric hit-test (robust): distance in screen space to each node.
${indent}// Does NOT depend on the throttled shadow canvas, so hit areas always
${indent}// match the visuals regardless of zoom/pan timing.
${indent}var t = ${tx}(state.canvas);
${indent}var k = t.k;
${indent}var getVal = ${accessor}(state.nodeVal);
${indent}var rel = state.nodeRelSize || 1;
${indent}var ns = state.graphData.nodes;
${indent}var bestD = Infinity;
${indent}for (var i = 0; i < ns.length; i++) {
${indent}  var n = ns[i];
${indent}  if (n.x == null || n.y == null) continue;
${indent}  var sx = t.x + n.x * k;
${indent}  var sy = t.y + n.y * k;
${indent}  var rad = Math.sqrt(Math.max(0, getVal(n) || 1)) * rel;
${indent}  var dx = pointerPos.x - sx;
${indent}  var dy = pointerPos.y - sy;
${indent}  var d2 = dx * dx + dy * dy;
${indent}  if (d2 < rad * rad && d2 < bestD) {
${indent}    bestD = d2;
${indent}    obj = { type: 'Node', d: n };
${indent}  }
${indent}}
${indent}// Only fall back to the shadow-canvas color lookup when geometry has no hit.
${indent}if (!obj) {
${indent}  var pxScale = window.devicePixelRatio;
${indent}  var px = pointerPos.x > 0 && pointerPos.y > 0 ? shadowCtx.getImageData(pointerPos.x * pxScale, pointerPos.y * pxScale, 1, 1) : null;
${indent}  px && (obj = state.colorTracker.lookup(px.data));
${indent}}
${indent}return obj;`
}

let allApplied = true
for (const file of FILES) {
  let src = readFileSync(file, 'utf8')

  const isMjs = src.includes('accessorFn')
  const accessor = isMjs ? 'accessorFn' : 'index$3'
  const tx = isMjs ? 'zoomTransform' : 'transform'

  const m = src.match(/var getObjUnderPointer = function getObjUnderPointer\(\) \{\n(( )+)var obj = null;/)
  const indent = m ? m[1] : '      '

  const replacement = `var getObjUnderPointer = function getObjUnderPointer() {\n${newBody(indent, isMjs)}\n    };`

  const fnRe = /var getObjUnderPointer = function getObjUnderPointer\(\) \{[\s\S]*?return obj;\n    };/
  if (fnRe.test(src)) {
    src = src.replace(fnRe, replacement)
    writeFileSync(file, src)
    console.log(`[patch] ${file} rebuilt (${isMjs ? 'esm' : 'cjs'} dialect, indent ${indent.length})`)
    continue
  }

  // Fallback: marker already present but body shape differs.
  if (src.includes(`var getVal = ${accessor}(state.nodeVal)`)) {
    console.log(`[patch] ${file} already patched with matching dialect`)
    continue
  }
  if (src.includes('var getVal = ')) {
    console.error(`[patch] ${file}: geometric body present but with WRONG identifiers; needs manual fix`)
    allApplied = false
    continue
  }
  console.error(`[patch] ${file}: getObjUnderPointer block not found`)
  allApplied = false
}

process.exit(allApplied ? 0 : 1)