import React from 'react';
import {
  AbsoluteFill,
  Audio,
  Easing,
  Img,
  Sequence,
  interpolate,
  spring,
  staticFile,
  useCurrentFrame,
  useVideoConfig,
} from 'remotion';

const COLORS = {
  ink: '#071017',
  white: '#f5fbff',
  cyan: '#3cf2d0',
  blue: '#45a9ff',
  red: '#ff556a',
  muted: '#9eb1bf',
};

const ease = (frame: number, input: number[], output: number[]) =>
  interpolate(frame, input, output, {extrapolateLeft: 'clamp', extrapolateRight: 'clamp'});

const GlowGrid: React.FC = () => {
  const frame = useCurrentFrame();
  return (
    <AbsoluteFill
      style={{
        backgroundColor: COLORS.ink,
        backgroundImage:
          'linear-gradient(rgba(67,242,208,.055) 1px, transparent 1px), linear-gradient(90deg, rgba(67,242,208,.055) 1px, transparent 1px)',
        backgroundSize: '54px 54px',
        backgroundPosition: `${frame * -0.16}px ${frame * 0.08}px`,
      }}
    >
      <div
        style={{
          position: 'absolute',
          inset: -300,
          background:
            'radial-gradient(circle at 24% 25%, rgba(69,169,255,.18), transparent 34%), radial-gradient(circle at 82% 76%, rgba(60,242,208,.13), transparent 32%)',
        }}
      />
    </AbsoluteFill>
  );
};

const Logo: React.FC<{small?: boolean}> = ({small}) => (
  <div style={{display: 'flex', alignItems: 'center', gap: small ? 14 : 24}}>
    <div
      style={{
        width: small ? 50 : 82,
        height: small ? 50 : 82,
        border: `2px solid ${COLORS.cyan}`,
        borderRadius: small ? 14 : 22,
        display: 'grid',
        placeItems: 'center',
        boxShadow: `0 0 38px rgba(60,242,208,.22)`,
        fontWeight: 900,
        fontSize: small ? 25 : 42,
        color: COLORS.cyan,
      }}
    >
      X
    </div>
    <div style={{fontWeight: 850, fontSize: small ? 30 : 62, letterSpacing: -2}}>PandaX</div>
  </div>
);

const Intro: React.FC = () => {
  const frame = useCurrentFrame();
  const {fps} = useVideoConfig();
  const inSpring = spring({fps, frame, config: {damping: 16, stiffness: 90}});
  const fade = ease(frame, [0, 12, 115, 140], [0, 1, 1, 0]);
  return (
    <AbsoluteFill style={{color: COLORS.white, alignItems: 'center', justifyContent: 'center', opacity: fade}}>
      <GlowGrid />
      <div style={{zIndex: 2, transform: `translateY(${(1 - inSpring) * 70}px) scale(${0.9 + inSpring * 0.1})`}}>
        <Logo />
        <div style={{marginTop: 42, fontSize: 62, lineHeight: 1.08, fontWeight: 760, letterSpacing: -2.6, maxWidth: 980}}>
          Software ships fast.
          <br />
          <span style={{color: COLORS.cyan}}>Regulation should keep up.</span>
        </div>
      </div>
    </AbsoluteFill>
  );
};

type ShotProps = {
  duration: number;
  image: string;
  title: string;
  kicker: string;
  cursorFrom: [number, number];
  cursorTo: [number, number];
  zoom?: number;
  accent?: string;
};

const Cursor: React.FC<{x: number; y: number; click: number; color: string; scale: number}> = ({x, y, click, color, scale}) => (
  <div style={{position: 'absolute', left: x, top: y, width: 26, height: 32, zIndex: 8, transform: `scale(${scale})`, transformOrigin: 'top left'}}>
    <div
      style={{
        position: 'absolute',
        width: 28 + click * 36,
        height: 28 + click * 36,
        left: -9 - click * 18,
        top: -9 - click * 18,
        border: `2px solid ${color}`,
        borderRadius: '50%',
        opacity: 0.68 - click * 0.68,
      }}
    />
    <svg width="25" height="31" viewBox="0 0 25 31" style={{filter: 'drop-shadow(0 3px 3px rgba(0,0,0,.55))'}}>
      <path d="M2 1.5L22 20H13.5L9.5 29L5.5 27L9 18H2Z" fill="#fff" stroke="#071017" strokeWidth="2" strokeLinejoin="round" />
    </svg>
  </div>
);

const BrowserShot: React.FC<ShotProps> = ({duration, image, title, kicker, cursorFrom, cursorTo, zoom = 1.85, accent = COLORS.cyan}) => {
  const frame = useCurrentFrame();
  const {fps} = useVideoConfig();
  const enter = spring({fps, frame, config: {damping: 18, stiffness: 90}});
  const exit = ease(frame, [duration - 20, duration], [1, 0]);
  const cameraIn = spring({fps, frame: frame - 12, config: {damping: 20, stiffness: 64, mass: 1.1}});
  const progress = interpolate(frame, [28, duration - 36], [0, 1], {
    easing: Easing.inOut(Easing.cubic),
    extrapolateLeft: 'clamp',
    extrapolateRight: 'clamp',
  });
  const cursorX = ease(progress, [0, 1], [cursorFrom[0], cursorTo[0]]);
  const cursorY = ease(progress, [0, 1], [cursorFrom[1], cursorTo[1]]);
  const cameraZoom = 1 + (zoom - 1) * cameraIn;
  const focusX = 1130;
  const focusY = 450;
  const cameraX = (focusX - cursorX * cameraZoom) * cameraIn;
  const cameraY = (focusY - cursorY * cameraZoom) * cameraIn;
  const click = ease(frame % 92, [57, 63, 85], [0, 1, 0]);
  const titleIn = spring({fps, frame: frame - 9, config: {damping: 18, stiffness: 110}});

  return (
    <AbsoluteFill style={{color: COLORS.white, opacity: exit, overflow: 'hidden'}}>
      <GlowGrid />
      <div
        style={{
          position: 'absolute',
          inset: 0,
          transform: `translate(${cameraX}px, ${cameraY + (1 - enter) * 110}px) scale(${cameraZoom})`,
          transformOrigin: '0 0',
        }}
      >
        <div
          style={{
            position: 'absolute',
            width: 1580,
            height: 988,
            left: 170,
            top: 56,
            borderRadius: 24,
            background: '#0c1720',
            border: '1px solid rgba(255,255,255,.14)',
            boxShadow: '0 45px 120px rgba(0,0,0,.55)',
            overflow: 'hidden',
          }}
        >
          <div style={{height: 54, display: 'flex', alignItems: 'center', gap: 10, padding: '0 22px', background: '#111e28', borderBottom: '1px solid rgba(255,255,255,.1)'}}>
            <i style={{width: 13, height: 13, borderRadius: '50%', background: '#ff5f57'}} />
            <i style={{width: 13, height: 13, borderRadius: '50%', background: '#febc2e'}} />
            <i style={{width: 13, height: 13, borderRadius: '50%', background: '#28c840'}} />
            <div style={{marginLeft: 22, width: 720, height: 28, borderRadius: 10, background: '#09131b', color: '#758795', fontSize: 14, display: 'grid', placeItems: 'center'}}>PandaX · CRA Compliance Vault</div>
          </div>
          <Img src={staticFile(`captures/${image}`)} style={{width: '100%', height: 934, objectFit: 'cover', objectPosition: 'top'}} />
        </div>
        <Cursor x={cursorX} y={cursorY} click={click} color={accent} scale={1 / cameraZoom} />
      </div>
      <div
        style={{
          position: 'absolute',
          left: 72,
          bottom: 65,
          width: 770,
          padding: '27px 34px 30px',
          background: 'rgba(5,13,19,.9)',
          border: `1px solid ${accent}55`,
          borderLeft: `7px solid ${accent}`,
          borderRadius: 18,
          backdropFilter: 'blur(18px)',
          transform: `translateX(${(1 - titleIn) * -90}px)`,
          opacity: titleIn,
          zIndex: 12,
        }}
      >
        <div style={{color: accent, fontWeight: 800, fontSize: 18, textTransform: 'uppercase', letterSpacing: 3}}>{kicker}</div>
        <div style={{fontSize: 44, fontWeight: 780, lineHeight: 1.08, letterSpacing: -1.4, marginTop: 9}}>{title}</div>
      </div>
      <div style={{position: 'absolute', inset: 0, boxShadow: `inset 0 0 180px ${accent}12`, pointerEvents: 'none'}} />
    </AbsoluteFill>
  );
};

const Outro: React.FC = () => {
  const frame = useCurrentFrame();
  const {fps} = useVideoConfig();
  const reveal = spring({fps, frame, config: {damping: 15, stiffness: 80}});
  return (
    <AbsoluteFill style={{color: COLORS.white, alignItems: 'center', justifyContent: 'center'}}>
      <GlowGrid />
      <div style={{zIndex: 2, textAlign: 'center', transform: `scale(${0.88 + reveal * 0.12})`, opacity: reveal}}>
        <div style={{display: 'flex', justifyContent: 'center'}}><Logo small /></div>
        <div style={{fontSize: 67, lineHeight: 1.07, fontWeight: 820, letterSpacing: -3, marginTop: 50}}>
          From artifact to
          <br />
          <span style={{color: COLORS.cyan}}>tamper-evident CRA evidence.</span>
        </div>
        <div style={{fontSize: 25, color: COLORS.muted, marginTop: 34, letterSpacing: 0.2}}>Inventory · Triage · Deadlines · Documents · Proof</div>
      </div>
    </AbsoluteFill>
  );
};

export const PandaXShowcase: React.FC = () => (
  <AbsoluteFill style={{fontFamily: 'Segoe UI, Arial, sans-serif', background: COLORS.ink}}>
    <Sequence durationInFrames={145}><Intro /></Sequence>
    <Sequence from={125} durationInFrames={285}>
      <BrowserShot duration={285} image="overview.png" kicker="Release readiness" title="One screen. Risk, evidence, next action." cursorFrom={[1570, 190]} cursorTo={[1190, 590]} zoom={1.78} />
    </Sequence>
    <Sequence from={390} durationInFrames={260}>
      <BrowserShot duration={260} image="findings.png" kicker="Exploit-aware triage" title="Active threats rise above the CVE noise." cursorFrom={[120, 250]} cursorTo={[990, 335]} accent={COLORS.red} zoom={1.95} />
    </Sequence>
    <Sequence from={630} durationInFrames={250}>
      <BrowserShot duration={250} image="inventory.png" kicker="Real release inventory" title="Every shipped component stays traceable." cursorFrom={[120, 195]} cursorTo={[910, 390]} accent={COLORS.blue} zoom={1.88} />
    </Sequence>
    <Sequence from={860} durationInFrames={270}>
      <BrowserShot duration={270} image="deadlines.png" kicker="Article 14" title="24h, 72h, 14d—deadlines stay visible." cursorFrom={[120, 300]} cursorTo={[920, 500]} accent="#ffc55f" zoom={2.02} />
    </Sequence>
    <Sequence from={1110} durationInFrames={245}>
      <BrowserShot duration={245} image="documents.png" kicker="Review-ready output" title="Dossier, declaration, SBOM and VEX—together." cursorFrom={[120, 410]} cursorTo={[900, 500]} zoom={1.82} />
    </Sequence>
    <Sequence from={1335} durationInFrames={300}>
      <BrowserShot duration={300} image="evidence.png" kicker="Cryptographic proof" title="Every stage chained. Every output sealed." cursorFrom={[120, 470]} cursorTo={[980, 565]} accent={COLORS.cyan} zoom={1.9} />
    </Sequence>
    <Sequence from={1605} durationInFrames={255}><Outro /></Sequence>
    <Audio src={staticFile('audio/pandax-voiceover.wav')} startFrom={0} playbackRate={0.94} volume={0.92} />
  </AbsoluteFill>
);
