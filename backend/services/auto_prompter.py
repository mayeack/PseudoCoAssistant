"""
Auto-Prompter Service
Automatically generates realistic medical consultation sessions for testing and demonstration.
"""

import asyncio
import math
import random
import time
import uuid
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict, Any
import httpx

from backend.config import settings

logger = logging.getLogger(__name__)


def _describe_error(e: BaseException) -> str:
    """Exception type plus message, so an empty-message error still says what it was."""
    msg = str(e)
    return f"{type(e).__name__}: {msg}" if msg else type(e).__name__


class AutoPrompterService:
    """Service that automatically creates sessions and sends realistic medical prompts"""

    # Per-request httpx timeout for the self-calls. Every generated turn runs the
    # Multi-Agent pipeline, which on Ollama took a median of about 22 s, a p90 of about
    # 32 s and up to 72 s in the October runs. The old 30 s limit dropped about half of the
    # sessions mid-conversation while the server finished each turn anyway. Same
    # budget as the incident load driver (routers/incident.py).
    TURN_TIMEOUT_S = 150.0

    # The generator turns itself off this long after it is switched on, so a
    # demo box left with the toggle on doesn't keep generating LLM traffic
    # indefinitely. Same idea as Trigger Demo Incident / Prompt Injection Spray.
    DEFAULT_DURATION_S = 3600

    # Realistic medical consultation scenarios with multi-turn conversations
    CONSULTATION_SCENARIOS = [
        {
            "initial": "I've been having really bad headaches for the past week",
            "followups": ["About 35 years old", "Maybe 5-6 days", "Pretty severe, like 7 out of 10", "No, no nausea or vision problems"]
        },
        {
            "initial": "My throat has been sore and I have a slight fever",
            "followups": ["I'm 28", "Started about 3 days ago", "Mild fever, around 100.2", "Yes, a bit of coughing too"]
        },
        {
            "initial": "I think I pulled a muscle in my lower back yesterday",
            "followups": ["42 years old", "Since yesterday afternoon", "Moderate pain, worse when I bend", "I was lifting some boxes"]
        },
        {
            "initial": "I've been feeling really tired lately, no matter how much I sleep",
            "followups": ["I'm 55", "For about 2-3 weeks now", "I sleep 8 hours but still exhausted", "No, appetite is normal"]
        },
        {
            "initial": "I have this rash on my arm that appeared overnight",
            "followups": ["31 years old", "Noticed it this morning", "It's red and slightly itchy", "No new detergents or foods"]
        },
        {
            "initial": "My stomach has been really upset and I feel nauseous",
            "followups": ["I'm 26", "Started last night", "Moderate nausea, some cramping", "Had takeout for dinner"]
        },
        {
            "initial": "I've been having trouble sleeping for the past few weeks",
            "followups": ["45 years old", "About 3 weeks", "Takes hours to fall asleep", "Yes, work has been stressful"]
        },
        {
            "initial": "My knee has been swelling and it hurts to walk",
            "followups": ["I'm 52", "For about a week now", "Moderate pain, stiffness in morning", "No injury that I remember"]
        },
        {
            "initial": "I keep getting dizzy when I stand up quickly",
            "followups": ["38 years old", "Past few days", "Lasts a few seconds each time", "I might not be drinking enough water"]
        },
        {
            "initial": "I have a persistent cough that won't go away",
            "followups": ["I'm 47", "About 2 weeks", "Dry cough, no mucus", "No fever, just the cough"]
        },
        {
            "initial": "I've been having chest tightness when I exercise",
            "followups": ["33 years old", "Started about a week ago", "Mild tightness, goes away when I rest", "No, no pain radiating anywhere"]
        },
        {
            "initial": "My child has had a runny nose and cough for several days",
            "followups": ["She's 6 years old", "About 4 days now", "Low grade fever, 99.5", "She's still eating and playing normally"]
        },
        {
            "initial": "I've noticed some numbness in my fingers occasionally",
            "followups": ["I'm 41", "On and off for a month", "Mostly in my pinky and ring finger", "I work at a computer all day"]
        },
        {
            "initial": "I've been experiencing frequent heartburn after meals",
            "followups": ["58 years old", "Past couple weeks", "Burns in my chest, worse lying down", "Mostly after dinner"]
        },
        {
            "initial": "I have a cut on my hand that doesn't seem to be healing well",
            "followups": ["I'm 62", "Cut it about 5 days ago", "It's red around the edges now", "Yes, I have type 2 diabetes"]
        },
        {
            "initial": "My anxiety has been really bad lately and I can't relax",
            "followups": ["29 years old", "Getting worse over past month", "Racing thoughts, trouble concentrating", "Starting a new job soon"]
        },
        {
            "initial": "I've been having sharp pains in my side when I breathe deeply",
            "followups": ["I'm 36", "Since yesterday", "Right side, under my ribs", "It hurts more when I take a deep breath"]
        },
        {
            "initial": "My eyes have been red and itchy for the past few days",
            "followups": ["44 years old", "About 3 days", "Both eyes, watery too", "Yes, allergies run in my family"]
        },
        {
            "initial": "I'm having trouble with my blood pressure medication side effects",
            "followups": ["I'm 67", "Started new medication 2 weeks ago", "Feeling lightheaded and tired", "Lisinopril, 10mg"]
        },
        {
            "initial": "I've noticed blood when I brush my teeth lately",
            "followups": ["39 years old", "Past week or so", "Gums look a bit swollen", "Haven't been to dentist in a while"]
        }
    ]
    
    def __init__(self):
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._sessions_created = 0
        self._last_session_time: Optional[datetime] = None
        # Run timer: the current (or last) run's length, when it started
        # (monotonic, for remaining_s) and when it ends (wall clock, for the API).
        self._duration_s: Optional[float] = None
        self._started_monotonic: Optional[float] = None
        self._expires_at: Optional[datetime] = None
        # True when the last run ended because its timer ran out, not via stop().
        self._auto_stopped = False
        # Derived from settings.port, not hardcoded 8001: on any other PORT the
        # toggle appeared to start but every self-call hit a dead port, so the
        # demo produced no traffic at all. (incident.py already did this.)
        self._base_url = f"http://127.0.0.1:{getattr(settings, 'port', 8001)}"
        
    @property
    def is_running(self) -> bool:
        return self._running
    
    @property
    def remaining_s(self) -> Optional[int]:
        """Whole seconds until the timer turns the generator off; None when stopped."""
        if not self._running or self._duration_s is None or self._started_monotonic is None:
            return None
        elapsed = time.monotonic() - self._started_monotonic
        return max(0, math.ceil(self._duration_s - elapsed))

    @property
    def stats(self) -> Dict[str, Any]:
        return {
            "running": self._running,
            "sessions_created": self._sessions_created,
            "last_session_time": self._last_session_time.isoformat() if self._last_session_time else None,
            "duration_s": int(self._duration_s) if self._duration_s is not None else None,
            "remaining_s": self.remaining_s,
            "expires_at": self._expires_at.isoformat() if (self._running and self._expires_at) else None,
            "auto_stopped": self._auto_stopped,
        }

    async def start(self, duration_s: Optional[float] = None):
        """Start the auto-prompter; it turns itself off after ``duration_s`` (default 60 min)."""
        if self._running:
            logger.warning("Auto-prompter is already running")
            return

        self._duration_s = float(duration_s) if duration_s else float(self.DEFAULT_DURATION_S)
        self._started_monotonic = time.monotonic()
        self._expires_at = datetime.now(timezone.utc) + timedelta(seconds=self._duration_s)
        self._auto_stopped = False
        self._running = True
        self._task = asyncio.create_task(self._run_for(self._duration_s))
        logger.info("Auto-prompter started (turns off after %d min)", int(self._duration_s // 60))

    async def stop(self):
        """Stop the auto-prompter"""
        if not self._running:
            logger.warning("Auto-prompter is not running")
            return

        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("Auto-prompter stopped")

    async def _run_for(self, duration_s: float):
        """Run the session loop until the timer runs out (or stop() cancels it).

        wait_for cancels the loop at the deadline, including a session that is
        mid-conversation; the server still finishes the turn it is serving.
        """
        try:
            await asyncio.wait_for(self._run_loop(), timeout=duration_s)
        except asyncio.TimeoutError:
            self._auto_stopped = True
            logger.info("Auto-prompter auto-stopped after %d min", int(duration_s) // 60)
        finally:
            self._running = False

    async def _run_loop(self):
        """Main loop that creates sessions every minute"""
        while self._running:
            try:
                await self._create_and_run_session()
                self._sessions_created += 1
                self._last_session_time = datetime.utcnow()
                logger.info(f"Auto-prompter: Session #{self._sessions_created} completed")
            except Exception as e:
                # Name the type: httpx timeouts stringify to "", which left a
                # bare "Auto-prompter error: " that read like a hang.
                logger.error("Auto-prompter error: %s", _describe_error(e))
            
            # Wait 60 seconds before next session
            if self._running:
                await asyncio.sleep(60)
    
    async def _create_and_run_session(self):
        """Create a new session and run through a realistic consultation"""
        # Authenticate the self-requests with the access key when the gate is on
        # (e.g. served via the tunnel); otherwise every generated turn 401s and no
        # demo traffic is produced. HTTP Basic: any username, key as the password.
        auth = ("auto-prompter", settings.access_key) if getattr(settings, "access_key", "") else None
        async with httpx.AsyncClient(timeout=self.TURN_TIMEOUT_S, auth=auth) as client:
            # Create new session
            response = await client.post(f"{self._base_url}/api/chat/session/new")
            response.raise_for_status()
            session_data = response.json()
            session_id = session_data["session_id"]
            
            logger.info(f"Auto-prompter: Created session {session_id}")
            
            # Select a random scenario
            scenario = random.choice(self.CONSULTATION_SCENARIOS)
            
            # Randomly decide if PII injection should be forced
            force_pii = random.choice([True, False, None])
            force_toxic = random.choice([True, False, None])
            force_hallucination = random.choice([True, False, None])
            
            # Send initial message
            await self._send_message(client, session_id, scenario["initial"], force_pii, force_toxic, force_hallucination)
            
            # Small delay between messages (simulate typing)
            await asyncio.sleep(random.uniform(1.0, 3.0))
            
            # Send follow-up messages
            for followup in scenario["followups"]:
                if not self._running:
                    break
                await self._send_message(client, session_id, followup, force_pii, force_toxic, force_hallucination)
                await asyncio.sleep(random.uniform(1.0, 3.0))
            
            logger.info(f"Auto-prompter: Session {session_id} conversation completed")
    
    async def _send_message(self, client: httpx.AsyncClient, session_id: str, message: str, force_pii: Optional[bool], force_toxic: Optional[bool], force_hallucination: Optional[bool]):
        """Send a single message to the chat API"""
        payload = {
            "session_id": session_id,
            "message": message,
            "disclaimer_accepted": True,
            "force_pii_injection": force_pii,
            "force_toxic_injection": force_toxic,
            "force_hallucination_injection": force_hallucination,
            # Auto-prompted demo traffic exists to populate AI Agent Monitoring
            # with multi-agent traces, so opt in explicitly (single-agent is the
            # API default).
            "multi_agent_mode": True
        }
        
        response = await client.post(
            f"{self._base_url}/api/chat/message",
            json=payload
        )
        response.raise_for_status()
        return response.json()


# Global instance
auto_prompter = AutoPrompterService()
