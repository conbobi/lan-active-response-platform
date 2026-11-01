import React from 'react';
import Agents from './Agents';

/**
 * Backward compatibility wrapper for legacy /groups route.
 * Redirects functionally to unified Endpoints & Host Groups page.
 */
export default function Groups() {
  return <Agents initialTab="groups" />;
}
