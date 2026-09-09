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
  secondCursorTarget?: [number, number];
  documentImage?: string;
  orbitRadius?: number;
  pipeline?: boolean;
  circle?: boolean;
  circleSecond?: boolean;
  zoom?: number;
  accent?: string;
};

const Cursor: React.FC<{x: number; y: number; click: number; color: string; scale: number}> = ({x, y, click, color, scale}) => (
  <div style={{position: 'absolute', left: x, top: y, width: 66, height: 72, zIndex: 8, transform: `scale(${scale})`, transformOrigin: '5px 4px'}}>
    <div
      style={{
        position: 'absolute',
        width: 30 + click * 54,
        height: 30 + click * 54,
        left: -11 - click * 27,
        top: -11 - click * 27,
        border: `3px solid ${color}`,
        borderRadius: '50%',
        opacity: click * 0.82,
      }}
    />
    <svg width="66" height="72" viewBox="0 0 740 740" style={{overflow: 'visible', filter: 'drop-shadow(0 7px 5px rgba(0,0,0,.48))'}}>
      <path d="M92 47L645 310L425 386L615 638L500 692L335 457L204 648Z" fill="#fff" stroke="#05080a" strokeWidth="42" strokeLinejoin="miter" />
    </svg>
  </div>
);

const orbit = (frame: number, start: number, duration: number, radius: number): [number, number] => {
  const progress = Math.max(0, Math.min(1, (frame - start) / duration));
  const angle = -Math.PI / 2 + progress * Math.PI * 2;
  return [Math.cos(angle) * radius, Math.sin(angle) * radius * 0.64];
};

const BrowserShot: React.FC<ShotProps> = ({
  duration,
  image,
  title,
  kicker,
  cursorFrom,
  cursorTo,
  secondCursorTarget,
  documentImage,
  orbitRadius = 92,
  pipeline = false,
  circle = true,
  circleSecond = true,
  zoom = 1.85,
  accent = COLORS.cyan,
}) => {
  const frame = useCurrentFrame();
  const {fps} = useVideoConfig();
  const isDocumentShot = image === 'documents.png';
  const activeCursorTo: [number, number] = isDocumentShot ? [1240, 550] : cursorTo;
  const activeSecondTarget = secondCursorTarget ?? (isDocumentShot ? [910, 300] as [number, number] : undefined);
  const activeDocumentImage = documentImage ?? (isDocumentShot ? 'eu-declaration.png' : undefined);
  const activeOrbitRadius = isDocumentShot ? 108 : orbitRadius;
  const activeKicker = isDocumentShot ? 'EU market readiness' : kicker;
  const activeTitle = isDocumentShot ? 'Open the declaration. See the blocker instantly.' : title;
  const activeAccent = isDocumentShot ? COLORS.red : accent;
  const activeZoom = isDocumentShot ? 1.92 : zoom;
  const activeDuration = isDocumentShot ? 390 : duration;
  const enter = spring({fps, frame, config: {damping: 18, stiffness: 90}});
  const exit = ease(frame, [activeDuration - 20, activeDuration], [1, 0]);
  const cameraIn = spring({fps, frame: frame - 12, config: {damping: 20, stiffness: 64, mass: 1.1}});
  const firstMove = interpolate(frame, [12, 36], [0, 1], {
    easing: Easing.out(Easing.cubic),
    extrapolateLeft: 'clamp',
    extrapolateRight: 'clamp',
  });
  const [firstOrbitX, firstOrbitY] = orbit(frame, 42, 54, activeSecondTarget || !circle ? 0 : activeOrbitRadius);
  const secondMove = interpolate(frame, [108, 132], [0, 1], {
    easing: Easing.inOut(Easing.cubic),
    extrapolateLeft: 'clamp',
    extrapolateRight: 'clamp',
  });
  const [secondOrbitX, secondOrbitY] = activeSecondTarget ? orbit(frame, 138, 62, circleSecond ? activeOrbitRadius * 0.8 : 0) : [0, 0];
  const firstX = ease(firstMove, [0, 1], [cursorFrom[0], activeCursorTo[0] + firstOrbitX]);
  const firstY = ease(firstMove, [0, 1], [cursorFrom[1], activeCursorTo[1] + firstOrbitY]);
  const targetX = activeSecondTarget ? ease(secondMove, [0, 1], [activeCursorTo[0], activeSecondTarget[0] + secondOrbitX]) : activeCursorTo[0];
  const targetY = activeSecondTarget ? ease(secondMove, [0, 1], [activeCursorTo[1], activeSecondTarget[1] + secondOrbitY]) : activeCursorTo[1];
  const cursorX = activeSecondTarget && frame >= 108 ? targetX : firstX;
  const cursorY = activeSecondTarget && frame >= 108 ? targetY : firstY;
  const cameraZoom = 1 + (activeZoom - 1) * cameraIn;
  const focusX = 1130;
  const focusY = 450;
  const cameraX = (focusX - cursorX * cameraZoom) * cameraIn;
  const cameraY = (focusY - cursorY * cameraZoom) * cameraIn;
  const firstClick = ease(frame, [34, 39, 56], [0, 1, 0]);
  const secondClick = activeSecondTarget && circleSecond ? ease(frame, [130, 135, 152], [0, 1, 0]) : 0;
  const click = Math.max(firstClick, secondClick);
  const titleIn = spring({fps, frame: frame - 9, config: {damping: 18, stiffness: 110}});
  const documentIn = spring({fps, frame: frame - 104, config: {damping: 18, stiffness: 105}});
  const pipelineOut = ease(frame, [166, 190], [1, 0]);

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
        {pipeline ? (
          <div
            style={{
              position: 'absolute',
              left: 438,
              top: 282,
              width: 1280,
              height: 530,
              zIndex: 4,
              borderRadius: 18,
              background: '#f7f9fc',
              border: '1px solid #d9e1ec',
              boxShadow: '0 18px 50px rgba(7,16,23,.16)',
              opacity: pipelineOut,
              padding: '42px 48px',
              color: '#071017',
            }}
          >
            <div style={{fontSize: 19, fontWeight: 800, color: COLORS.blue, letterSpacing: 2.4, textTransform: 'uppercase'}}>Analysis running</div>
            <div style={{fontSize: 38, fontWeight: 820, marginTop: 8}}>Building the CRA evidence chain</div>
            <div style={{display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 18, marginTop: 34}}>
              {['Inventory product', 'Match vulnerabilities', 'Check active exploitation', 'Generate and seal documents'].map((label, index) => {
                const active = frame >= 48 + index * 27;
                return (
                  <div key={label} style={{display: 'flex', alignItems: 'center', gap: 15, padding: '19px 22px', borderRadius: 13, background: '#fff', border: `1px solid ${active ? '#8ad8ca' : '#e4e9ef'}`, color: active ? '#08715f' : '#7d8994', fontSize: 21, fontWeight: 720}}>
                    <span style={{width: 28, height: 28, borderRadius: '50%', display: 'grid', placeItems: 'center', color: '#fff', background: active ? '#0aa386' : '#c9d1da'}}>{active ? '✓' : index + 1}</span>
                    {label}
                  </div>
                );
              })}
            </div>
          </div>
        ) : null}
        {activeDocumentImage ? (
          <>
            <div style={{position: 'absolute', inset: 0, zIndex: 5, background: 'rgba(3,8,12,.82)', opacity: documentIn}} />
            <div
              style={{
                position: 'absolute',
                left: 500,
                top: 28,
                width: 820,
                zIndex: 6,
                borderRadius: 8,
                overflow: 'hidden',
                background: '#fff',
                boxShadow: '0 38px 100px rgba(0,0,0,.68)',
                opacity: documentIn,
                transform: `translate(${(1 - documentIn) * 315}px, ${(1 - documentIn) * 250}px) scale(${0.42 + documentIn * 0.58})`,
                transformOrigin: '72% 45%',
              }}
            >
              <Img src={staticFile(`captures/${activeDocumentImage}`)} style={{display: 'block', width: '100%'}} />
            </div>
          </>
        ) : null}
        <Cursor x={cursorX} y={cursorY} click={click} color={activeAccent} scale={1 / cameraZoom} />
      </div>
      <div
        style={{
          position: 'absolute',
          left: 72,
          bottom: 65,
          width: 770,
          padding: '27px 34px 30px',
          background: 'rgba(5,13,19,.9)',
          border: `1px solid ${activeAccent}55`,
          borderLeft: `7px solid ${activeAccent}`,
          borderRadius: 18,
          backdropFilter: 'blur(18px)',
          transform: `translateX(${(1 - titleIn) * -90}px)`,
          opacity: titleIn,
          zIndex: 12,
        }}
      >
        <div style={{color: activeAccent, fontWeight: 800, fontSize: 18, textTransform: 'uppercase', letterSpacing: 3}}>{activeKicker}</div>
        <div style={{fontSize: 44, fontWeight: 780, lineHeight: 1.08, letterSpacing: -1.4, marginTop: 9}}>{activeTitle}</div>
      </div>
      <div style={{position: 'absolute', inset: 0, boxShadow: `inset 0 0 180px ${activeAccent}12`, pointerEvents: 'none'}} />
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
    <Sequence durationInFrames={110}><Intro /></Sequence>
    <Sequence from={100} durationInFrames={300}>
      <BrowserShot duration={300} image="overview.png" kicker="Run the product" title="One click starts the full evidence pipeline." cursorFrom={[1220, 235]} cursorTo={[1650, 235]} secondCursorTarget={[1050, 570]} zoom={1.72} pipeline circle={false} circleSecond={false} />
    </Sequence>
    <Sequence from={380} durationInFrames={225}>
      <BrowserShot duration={225} image="overview.png" kicker="Immediate alert" title="One exploited threat becomes the release blocker." cursorFrom={[930, 535]} cursorTo={[1250, 535]} accent={COLORS.red} zoom={2.02} orbitRadius={96} />
    </Sequence>
    <Sequence from={585} durationInFrames={240}>
      <BrowserShot duration={240} image="overview.png" kicker="Clear next action" title="Upgrade once. Clear twenty-two findings." cursorFrom={[680, 765]} cursorTo={[930, 765]} accent={COLORS.blue} zoom={2.05} orbitRadius={118} />
    </Sequence>
    <Sequence from={2000} durationInFrames={270}>
      <BrowserShot duration={270} image="deadlines.png" kicker="Article 14" title="24h, 72h, 14d—deadlines stay visible." cursorFrom={[120, 300]} cursorTo={[920, 500]} accent="#ffc55f" zoom={2.02} />
    </Sequence>
    <Sequence from={805} durationInFrames={390}>
      <BrowserShot duration={245} image="documents.png" kicker="Review-ready output" title="Dossier, declaration, SBOM and VEX—together." cursorFrom={[120, 410]} cursorTo={[900, 500]} zoom={1.82} />
    </Sequence>
    <Sequence from={2000} durationInFrames={300}>
      <BrowserShot duration={300} image="evidence.png" kicker="Cryptographic proof" title="Every stage chained. Every output sealed." cursorFrom={[120, 470]} cursorTo={[980, 565]} accent={COLORS.cyan} zoom={1.9} />
    </Sequence>
    <Sequence from={1175} durationInFrames={235}><Outro /></Sequence>
    <Sequence><Audio src={staticFile('audio/intro.wav')} volume={0.98} /></Sequence>
    <Sequence from={105}><Audio src={staticFile('audio/pipeline.wav')} volume={0.98} /></Sequence>
    <Sequence from={383}><Audio src={staticFile('audio/alert.wav')} volume={0.98} /></Sequence>
    <Sequence from={588}><Audio src={staticFile('audio/upgrade.wav')} volume={0.98} /></Sequence>
    <Sequence from={808}><Audio src={staticFile('audio/document.wav')} volume={0.98} /></Sequence>
    <Sequence from={1185}><Audio src={staticFile('audio/outro.wav')} volume={0.98} /></Sequence>
  </AbsoluteFill>
);
