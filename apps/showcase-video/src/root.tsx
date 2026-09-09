import React from 'react';
import {Composition} from 'remotion';
import {PandaXShowcase} from './showcase';

export const Root: React.FC = () => (
  <Composition
    id="PandaXShowcase"
    component={PandaXShowcase}
    durationInFrames={1410}
    fps={30}
    width={1920}
    height={1080}
  />
);
