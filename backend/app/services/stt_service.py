import os
import io
import wave
import logging
from groq import Groq

logger = logging.getLogger("satrk.stt")


def create_wav_bytes(pcm_bytes: bytes, sample_rate: int = 16000, num_channels: int = 1, sample_width: int = 2) -> bytes:
    """
    Wraps raw PCM 16-bit audio bytes in a standard 44-byte WAV container.
    """
    buf = io.BytesIO()
    with wave.open(buf, 'wb') as wav_file:
        wav_file.setnchannels(num_channels)
        wav_file.setsampwidth(sample_width)
        wav_file.setframerate(sample_rate)
        wav_file.writeframes(pcm_bytes)
    return buf.getvalue()


class STTService:
    def __init__(self, api_key: str = None):
        self.client = Groq(api_key=api_key or os.environ.get("GROQ_API_KEY"))

    async def transcribe_audio(self, audio_bytes: bytes, filename: str = "audio.webm") -> str:
        """
        Transcribes audio bytes to text via Groq Whisper API.
        Automatically detects WebM, Ogg, WAV headers, or wraps raw PCM in WAV format.
        """
        if not audio_bytes or len(audio_bytes) < 100:
            return ""

        try:
            # Detect media format by magic bytes
            if audio_bytes.startswith(b'\x1a\x45\xdf\xa3'):
                target_filename = "audio.webm"
                target_bytes = audio_bytes
            elif audio_bytes.startswith(b'OggS'):
                target_filename = "audio.ogg"
                target_bytes = audio_bytes
            elif audio_bytes.startswith(b'RIFF'):
                target_filename = "audio.wav"
                target_bytes = audio_bytes
            elif audio_bytes.startswith(b'ftyp') or (len(audio_bytes) > 8 and audio_bytes[4:8] == b'ftyp'):
                target_filename = "audio.mp4"
                target_bytes = audio_bytes
            else:
                # Raw PCM 16-bit 16kHz audio from Android AudioRecord
                target_filename = "audio.wav"
                target_bytes = create_wav_bytes(audio_bytes, sample_rate=16000, num_channels=1, sample_width=2)

            file_tuple = (target_filename, target_bytes)
            response = self.client.audio.transcriptions.create(
                file=file_tuple,
                model="whisper-large-v3",
                response_format="text"
            )

            if isinstance(response, str):
                return response.strip()
            return response.get("text", "").strip()

        except Exception as e:
            logger.warning(f"STT Service transcription skipped invalid chunk: {e}")
            return ""