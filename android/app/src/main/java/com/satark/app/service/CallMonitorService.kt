package com.satark.app.service

import android.annotation.SuppressLint
import android.app.*
import android.content.Context
import android.content.Intent
import android.media.AudioFormat
import android.media.AudioRecord
import android.media.MediaRecorder
import android.os.Build
import android.os.IBinder
import android.util.Log
import androidx.core.app.NotificationCompat
import com.satark.app.network.CallAnalysisCallback
import com.satark.app.network.CallAnalysisResult
import com.satark.app.network.CallWebSocketClient
import java.util.concurrent.atomic.AtomicBoolean

class CallMonitorService : Service(), CallAnalysisCallback {

    private var webSocketClient: CallWebSocketClient? = null
    private var audioRecord: AudioRecord? = null
    private var recordingThread: Thread? = null
    private val isRecording = AtomicBoolean(false)

    private var serverIp: String = CallWebSocketClient.DEFAULT_SERVER_IP
    private var serverPort: Int = 8000
    private var callId: String = ""

    companion object {
        private const val TAG = "CallMonitorService"
        private const val CHANNEL_ID = "SatarkCallMonitorChannel"
        private const val NOTIFICATION_ID = 1001

        const val ACTION_START_MONITORING = "com.satark.app.action.START_MONITORING"
        const val ACTION_STOP_MONITORING = "com.satark.app.action.STOP_MONITORING"
        const val EXTRA_SERVER_IP = "extra_server_ip"
        const val EXTRA_SERVER_PORT = "extra_server_port"
        const val EXTRA_CALL_ID = "extra_call_id"

        const val SAMPLE_RATE = 16000
        const val CHANNEL_CONFIG = AudioFormat.CHANNEL_IN_MONO
        const val AUDIO_FORMAT = AudioFormat.ENCODING_PCM_16BIT
    }

    override fun onCreate() {
        super.onCreate()
        Log.i(TAG, "CallMonitorService Created.")
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent == null) return START_NOT_STICKY

        when (intent.action) {
            ACTION_START_MONITORING -> {
                serverIp = intent.getStringExtra(EXTRA_SERVER_IP) ?: CallWebSocketClient.DEFAULT_SERVER_IP
                serverPort = intent.getIntExtra(EXTRA_SERVER_PORT, 8000)
                callId = intent.getStringExtra(EXTRA_CALL_ID) ?: "call_${System.currentTimeMillis()}"

                Log.i(TAG, "Starting call monitoring service for callId: $callId, target: $serverIp:$serverPort")
                startForegroundServiceNotification()
                startMonitoring()
            }
            ACTION_STOP_MONITORING -> {
                Log.i(TAG, "Stopping call monitoring service via Intent...")
                stopSelf()
            }
        }

        return START_STICKY
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Satark Call Protection Service",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Monitors live call audio in background for digital arrest scam detection."
            }
            val notificationManager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            notificationManager.createNotificationChannel(channel)
        }
    }

    private fun startForegroundServiceNotification() {
        val notification: Notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Satark Live Call Shield Active")
            .setContentText("Monitoring live call audio for cyber threat detection...")
            .setSmallIcon(android.R.drawable.ic_btn_speak_now)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()

        startForeground(NOTIFICATION_ID, notification)
    }

    private fun updateNotificationAlert(result: CallAnalysisResult) {
        if (result.isAlert) {
            val alertNotification: Notification = NotificationCompat.Builder(this, CHANNEL_ID)
                .setContentTitle("⚠️ CRITICAL SCAM ALERT DETECTED!")
                .setContentText("Risk Score: ${result.riskScore.toInt()}% - ${result.hits.joinToString()}")
                .setSmallIcon(android.R.drawable.stat_sys_warning)
                .setPriority(NotificationCompat.PRIORITY_HIGH)
                .setVibrate(longArrayOf(0, 500, 200, 500))
                .build()

            val notificationManager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            notificationManager.notify(NOTIFICATION_ID, alertNotification)
        }
    }

    @SuppressLint("MissingPermission")
    private fun startMonitoring() {
        if (isRecording.get()) {
            Log.w(TAG, "Call monitoring is already running.")
            return
        }

        // Initialize WebSocket Client
        webSocketClient = CallWebSocketClient()
        webSocketClient?.connect(serverIp, serverPort, callId, this)

        // Initialize AudioRecord
        val minBufferSize = AudioRecord.getMinBufferSize(SAMPLE_RATE, CHANNEL_CONFIG, AUDIO_FORMAT)
        val bufferSize = maxOf(minBufferSize, SAMPLE_RATE * 2 * 2) // 2 seconds buffer chunks

        try {
            audioRecord = AudioRecord(
                MediaRecorder.AudioSource.MIC,
                SAMPLE_RATE,
                CHANNEL_CONFIG,
                AUDIO_FORMAT,
                bufferSize
            )

            if (audioRecord?.state != AudioRecord.STATE_INITIALIZED) {
                Log.e(TAG, "AudioRecord initialization failed!")
                return
            }

            audioRecord?.startRecording()
            isRecording.set(true)

            // Background worker thread for audio buffer streaming
            recordingThread = Thread({
                val audioBuffer = ByteArray(bufferSize)
                Log.i(TAG, "Audio recording thread started. Buffer size: $bufferSize bytes.")

                while (isRecording.get()) {
                    val bytesRead = audioRecord?.read(audioBuffer, 0, audioBuffer.size) ?: 0
                    if (bytesRead > 0) {
                        val chunk = if (bytesRead == audioBuffer.size) audioBuffer else audioBuffer.copyOf(bytesRead)
                        webSocketClient?.sendAudioChunk(chunk)
                    } else {
                        Log.w(TAG, "AudioRecord read returned non-positive value: $bytesRead")
                    }
                }
                Log.i(TAG, "Audio recording loop finished.")
            }, "SatarkAudioRecorderThread")

            recordingThread?.start()

        } catch (e: Exception) {
            Log.e(TAG, "Error starting AudioRecord: ${e.message}", e)
        }
    }

    override fun onAnalysisReceived(result: CallAnalysisResult) {
        Log.i(TAG, "Analysis Update -> Risk: ${result.riskScore}%, Alert: ${result.isAlert}, Transcript: ${result.transcript}")
        updateNotificationAlert(result)
    }

    override fun onError(error: String) {
        Log.e(TAG, "Call Monitoring WebSocket Error: $error")
    }

    override fun onClosed() {
        Log.i(TAG, "Call Monitoring WebSocket Closed.")
    }

    override fun onDestroy() {
        Log.i(TAG, "Tearing down CallMonitorService...")
        isRecording.set(false)

        try {
            recordingThread?.interrupt()
            recordingThread = null
        } catch (e: Exception) {
            Log.e(TAG, "Error stopping recording thread: ${e.message}")
        }

        try {
            if (audioRecord?.state == AudioRecord.STATE_INITIALIZED) {
                audioRecord?.stop()
            }
            audioRecord?.release()
            audioRecord = null
        } catch (e: Exception) {
            Log.e(TAG, "Error releasing AudioRecord: ${e.message}")
        }

        webSocketClient?.disconnect()
        webSocketClient = null

        stopForeground(STOP_FOREGROUND_REMOVE)
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null
}
