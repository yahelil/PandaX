import React from 'react';
import {Composition} from 'remotion';
import {ActisDashboardDemo} from './showcase';

export const Root: React.FC = () => (
  <Composition
    id="ActisDashboardDemo"
    component={ActisDashboardDemo}
    durationInFrames={2040}
    fps={30}
    width={1920}
    height={1080}
  />
);
