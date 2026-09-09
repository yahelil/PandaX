import React from 'react';
import {
  AbsoluteFill,
  Audio,
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

const Cursor: React.FC<{x: number; y: number; click: number; color: string}> = ({x, y, click, color}) => (
  <div style={{position: 'absolute', left: x, top: y, width: 48, height: 48, zIndex: 8}}>
    <div
      style={{
        position: 'absolute',
        width: 52 + click * 55,
        height: 52 + click * 55,
        left: -18 - click * 27.5,
        top: -18 - click * 27.5,
        border: `3px solid ${color}`,
        borderRadius: '50%',
        opacity: 0.8 - click * 0.8,
      }}
    />
    <svg width="42" height="52" viewBox="0 0 42 52" style={{filter: 'drop-shadow(0 5px 6px rgba(0,0,0,.55))'}}>
      <path d="M4 2L35 31H21L15 47L8 44L14 29H4Z" fill="#fff" stroke="#071017" strokeWidth="3" strokeLinejoin="round" />
    </svg>
  </div>
);

const BrowserShot: React.FC<ShotProps> = ({duration, image, title, kicker, cursorFrom, cursorTo, zoom = 1.16, accent = COLORS.cyan}) => {
  const frame = useCurrentFrame();
  const {fps} = useVideoConfig();
  const enter = spring({fps, frame, config: {damping: 18, stiffness: 90}});
  const exit = ease(frame, [duration - 20, duration], [1, 0]);
  const progress = ease(frame, [18, duration - 22], [0, 1]);
  const cursorX = ease(progress, [0, 1], [cursorFrom[0], cursorTo[0]]);
  const cursorY = ease(progress, [0, 1], [cursorFrom[1], cursorTo[1]]);
  const camX = ease(progress, [0, 1], [(960 - cursorFrom[0]) * 0.08, (960 - cursorTo[0]) * 0.18]);
  const camY = ease(progress, [0, 1], [(540 - cursorFrom[1]) * 0.06, (540 - cursorTo[1]) * 0.14]);
  const click = ease(frame % 55, [34, 46, 54], [0, 1, 0]);
  const titleIn = spring({fps, frame: frame - 9, config: {damping: 18, stiffness: 110}});

  return (
    <AbsoluteFill style={{color: COLORS.white, opacity: exit, overflow: 'hidden'}}>
      <GlowGrid />
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
          transform: `translate(${camX}px, ${camY + (1 - enter) * 120}px) scale(${(0.91 + enter * 0.09) * (1 + (zoom - 1) * progress)})`,
          transformOrigin: `${cursorTo[0] / 1920 * 100}% ${cursorTo[1] / 1080 * 100}%`,
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
      <Cursor x={cursorX} y={cursorY} click={click} color={accent} />
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
      <BrowserShot duration={285} image="overview.png" kicker="Release readiness" title="One screen. Risk, evidence, next action." cursorFrom={[1580, 180]} cursorTo={[1310, 505]} />
    </Sequence>
    <Sequence from={390} durationInFrames={260}>
      <BrowserShot duration={260} image="findings.png" kicker="Exploit-aware triage" title="Active threats rise above the CVE noise." cursorFrom={[140, 240]} cursorTo={[1040, 425]} accent={COLORS.red} zoom={1.2} />
    </Sequence>
    <Sequence from={630} durationInFrames={250}>
      <BrowserShot duration={250} image="inventory.png" kicker="Real release inventory" title="Every shipped component stays traceable." cursorFrom={[140, 180]} cursorTo={[850, 485]} accent={COLORS.blue} />
    </Sequence>
    <Sequence from={860} durationInFrames={270}>
      <BrowserShot duration={270} image="deadlines.png" kicker="Article 14" title="24h, 72h, 14d—deadlines stay visible." cursorFrom={[140, 300]} cursorTo={[1030, 515]} accent="#ffc55f" zoom={1.18} />
    </Sequence>
    <Sequence from={1110} durationInFrames={245}>
      <BrowserShot duration={245} image="documents.png" kicker="Review-ready output" title="Dossier, declaration, SBOM and VEX—together." cursorFrom={[140, 415]} cursorTo={[1020, 450]} />
    </Sequence>
    <Sequence from={1335} durationInFrames={300}>
      <BrowserShot duration={300} image="evidence.png" kicker="Cryptographic proof" title="Every stage chained. Every output sealed." cursorFrom={[140, 470]} cursorTo={[1220, 430]} accent={COLORS.cyan} zoom={1.22} />
    </Sequence>
    <Sequence from={1605} durationInFrames={255}><Outro /></Sequence>
    <Audio src={staticFile('audio/pandax-voiceover.wav')} startFrom={0} playbackRate={1.1} volume={0.92} />
  </AbsoluteFill>
);
