// Static wireframe backdrop, shared identity with escaliba.net. Renders one
// frame of a simplex-noise terrain behind the page margins; no animation loop.
// Degrades to nothing if WebGL is unavailable.

const VERT = `
precision highp float;
attribute vec2 a_grid;
uniform float u_time;
uniform float u_aspect;
varying float v_fade;
varying float v_light;
vec3 mod289(vec3 x){return x-floor(x*(1.0/289.0))*289.0;}
vec4 mod289(vec4 x){return x-floor(x*(1.0/289.0))*289.0;}
vec4 permute(vec4 x){return mod289(((x*34.0)+10.0)*x);}
vec4 taylorInvSqrt(vec4 r){return 1.79284291400159-0.85373472095314*r;}
float snoise(vec3 v){
  const vec2 C=vec2(1.0/6.0,1.0/3.0);
  const vec4 D=vec4(0.0,0.5,1.0,2.0);
  vec3 i=floor(v+dot(v,C.yyy));
  vec3 x0=v-i+dot(i,C.xxx);
  vec3 g=step(x0.yzx,x0.xyz);
  vec3 l=1.0-g;
  vec3 i1=min(g.xyz,l.zxy);
  vec3 i2=max(g.xyz,l.zxy);
  vec3 x1=x0-i1+C.xxx;
  vec3 x2=x0-i2+C.yyy;
  vec3 x3=x0-D.yyy;
  i=mod289(i);
  vec4 p=permute(permute(permute(i.z+vec4(0.0,i1.z,i2.z,1.0))+i.y+vec4(0.0,i1.y,i2.y,1.0))+i.x+vec4(0.0,i1.x,i2.x,1.0));
  float n_=0.142857142857;
  vec3 ns=n_*D.wyz-D.xzx;
  vec4 j=p-49.0*floor(p*ns.z*ns.z);
  vec4 x_=floor(j*ns.z);
  vec4 y_=floor(j-7.0*x_);
  vec4 x=x_*ns.x+ns.yyyy;
  vec4 y=y_*ns.x+ns.yyyy;
  vec4 h=1.0-abs(x)-abs(y);
  vec4 b0=vec4(x.xy,y.xy);
  vec4 b1=vec4(x.zw,y.zw);
  vec4 s0=floor(b0)*2.0+1.0;
  vec4 s1=floor(b1)*2.0+1.0;
  vec4 sh=-step(h,vec4(0.0));
  vec4 a0=b0.xzyw+s0.xzyw*sh.xxyy;
  vec4 a1=b1.xzyw+s1.xzyw*sh.zzww;
  vec3 p0=vec3(a0.xy,h.x);
  vec3 p1=vec3(a0.zw,h.y);
  vec3 p2=vec3(a1.xy,h.z);
  vec3 p3=vec3(a1.zw,h.w);
  vec4 norm=taylorInvSqrt(vec4(dot(p0,p0),dot(p1,p1),dot(p2,p2),dot(p3,p3)));
  p0*=norm.x;p1*=norm.y;p2*=norm.z;p3*=norm.w;
  vec4 m=max(0.5-vec4(dot(x0,x0),dot(x1,x1),dot(x2,x2),dot(x3,x3)),0.0);
  m=m*m;
  return 105.0*dot(m*m,vec4(dot(p0,x0),dot(p1,x1),dot(p2,x2),dot(p3,x3)));
}
float terrain(vec2 p){
  return snoise(vec3(p*0.07,u_time*0.018))*1.7
       + snoise(vec3(p*0.16+11.7,u_time*0.03))*0.55
       + snoise(vec3(p*0.4-4.3,u_time*0.045))*0.12;
}
float height(vec2 g){
  float calm=mix(0.16,1.0,smoothstep(4.0,17.0,g.y));
  return terrain(vec2(g.x,g.y))*calm;
}
void main(){
  float z=mix(3.0,44.0,pow(a_grid.y,1.55));
  float x=(a_grid.x-0.5)*2.0*(5.0+z*0.95);
  vec2 g=vec2(x,z);
  float h=height(g);
  float e=0.35;
  float hx=height(g+vec2(e,0.0))-height(g-vec2(e,0.0));
  float hz=height(g+vec2(0.0,e))-height(g-vec2(0.0,e));
  vec3 n=normalize(vec3(-hx,2.0*e,-hz));
  v_light=pow(max(dot(n,normalize(vec3(-0.4,0.7,0.6))),0.0),2.5);
  float pitch=0.2;
  vec3 v=vec3(x,h,z)-vec3(0.0,3.2,0.0);
  v=vec3(v.x,cos(pitch)*v.y+sin(pitch)*v.z,-sin(pitch)*v.y+cos(pitch)*v.z);
  float f=2.1445;
  gl_Position=vec4(v.x*f/u_aspect,v.y*f,0.0,v.z);
  v_fade=(1.0-smoothstep(14.0,44.0,z))*smoothstep(3.0,6.0,z);
}`;

const FRAG = `
precision mediump float;
uniform vec3 u_base;
uniform vec3 u_accent;
uniform float u_alpha;
uniform vec4 u_rect0;
uniform float u_soft;
uniform float u_inner;
varying float v_fade;
varying float v_light;
float outside(vec4 r){
  vec2 d=max(max(r.xy-gl_FragCoord.xy,gl_FragCoord.xy-r.zw),0.0);
  return length(d);
}
void main(){
  float mask=mix(u_inner,1.0,smoothstep(0.0,u_soft,outside(u_rect0)));
  float a=u_alpha*v_fade*(0.3+0.7*v_light)*mask;
  vec3 c=mix(u_base,u_accent,smoothstep(0.35,0.95,v_light)*0.6);
  gl_FragColor=vec4(c*a,a);
}`;

const COLS = 150;
const ROWS = 80;
const canvas = document.querySelector("[data-mesh]");
const gl =
  canvas &&
  canvas.getContext("webgl", { antialias: true, alpha: true, premultipliedAlpha: true, powerPreference: "low-power" });

function compile(type, src) {
  const s = gl.createShader(type);
  gl.shaderSource(s, src);
  gl.compileShader(s);
  return gl.getShaderParameter(s, gl.COMPILE_STATUS) ? s : null;
}

const program =
  gl &&
  (() => {
    const vs = compile(gl.VERTEX_SHADER, VERT);
    const fs = compile(gl.FRAGMENT_SHADER, FRAG);
    if (!vs || !fs) return null;
    const p = gl.createProgram();
    gl.attachShader(p, vs);
    gl.attachShader(p, fs);
    gl.linkProgram(p);
    return gl.getProgramParameter(p, gl.LINK_STATUS) ? p : null;
  })();

if (canvas && gl && program) {
  const root = document.documentElement;
  const grid = new Float32Array(COLS * ROWS * 2);
  for (let j = 0; j < ROWS; j++)
    for (let i = 0; i < COLS; i++) {
      grid[(j * COLS + i) * 2] = i / (COLS - 1);
      grid[(j * COLS + i) * 2 + 1] = j / (ROWS - 1);
    }
  const lines = [];
  for (let j = 0; j < ROWS; j++)
    for (let i = 0; i < COLS; i++) {
      const k = j * COLS + i;
      if (i < COLS - 1) lines.push(k, k + 1);
      if (j < ROWS - 1) lines.push(k, k + COLS);
      if (i < COLS - 1 && j < ROWS - 1) lines.push(k, k + COLS + 1);
    }
  const indices = new Uint16Array(lines);

  gl.useProgram(program);
  gl.bindBuffer(gl.ARRAY_BUFFER, gl.createBuffer());
  gl.bufferData(gl.ARRAY_BUFFER, grid, gl.STATIC_DRAW);
  const aGrid = gl.getAttribLocation(program, "a_grid");
  gl.enableVertexAttribArray(aGrid);
  gl.vertexAttribPointer(aGrid, 2, gl.FLOAT, false, 0, 0);
  gl.bindBuffer(gl.ELEMENT_ARRAY_BUFFER, gl.createBuffer());
  gl.bufferData(gl.ELEMENT_ARRAY_BUFFER, indices, gl.STATIC_DRAW);
  gl.enable(gl.BLEND);
  gl.blendFunc(gl.ONE, gl.ONE_MINUS_SRC_ALPHA);
  gl.clearColor(0, 0, 0, 0);

  const u = (name) => gl.getUniformLocation(program, name);
  const U = { time: u("u_time"), aspect: u("u_aspect"), base: u("u_base"), accent: u("u_accent"), alpha: u("u_alpha"), rect0: u("u_rect0"), soft: u("u_soft"), inner: u("u_inner") };
  const seed = Math.random() * 100;

  const rgb = (value, fallback) => {
    const parts = value.trim().split(/\s+/).map(Number);
    return parts.length === 3 && parts.every((n) => !Number.isNaN(n)) ? parts.map((n) => n / 255) : fallback;
  };
  function readTheme() {
    const cs = getComputedStyle(root);
    gl.uniform3fv(U.base, rgb(cs.getPropertyValue("--mesh-rgb"), [0.92, 0.91, 0.89]));
    gl.uniform3fv(U.accent, rgb(cs.getPropertyValue("--mesh-accent-rgb"), [0.56, 0.66, 0.96]));
    gl.uniform1f(U.alpha, Number(cs.getPropertyValue("--mesh-alpha")) || 0.26);
    gl.uniform1f(U.time, seed);
  }

  const NONE = [-1e5, -1e5, -1e5, -1e5];
  function glRect(el, pad) {
    if (!el) return NONE;
    const r = el.getBoundingClientRect();
    if (!r.width || !r.height) return NONE;
    const dpr = canvas.width / canvas.clientWidth;
    const h = canvas.height;
    return [(r.left - pad) * dpr, h - (r.bottom + pad) * dpr, (r.right + pad) * dpr, h - (r.top - pad) * dpr];
  }
  function clearRects() {
    const main = document.querySelector("main");
    const header = document.querySelector(".site-header");
    const a = glRect(main, 26);
    const b = glRect(header, 26);
    const rect = a === NONE ? b : b === NONE ? a : [Math.min(a[0], b[0]), Math.min(a[1], b[1]), Math.max(a[2], b[2]), Math.max(a[3], b[3])];
    gl.uniform4fv(U.rect0, rect);
  }
  function resize() {
    const dpr = Math.min(devicePixelRatio || 1, 2);
    const w = canvas.clientWidth;
    const h = canvas.clientHeight;
    if (!w || !h) return false;
    canvas.width = Math.round(w * dpr);
    canvas.height = Math.round(h * dpr);
    gl.viewport(0, 0, canvas.width, canvas.height);
    gl.uniform1f(U.aspect, w / h);
    gl.uniform1f(U.soft, 150 * dpr);
    gl.uniform1f(U.inner, 0.07);
    return true;
  }
  function draw() {
    if (getComputedStyle(canvas).display === "none" || !resize()) return;
    clearRects();
    gl.clear(gl.COLOR_BUFFER_BIT);
    gl.drawElements(gl.LINES, indices.length, gl.UNSIGNED_SHORT, 0);
    canvas.classList.add("is-ready");
  }

  readTheme();
  let timer = 0;
  addEventListener("resize", () => {
    clearTimeout(timer);
    timer = setTimeout(draw, 160);
  });
  requestAnimationFrame(draw);
}
