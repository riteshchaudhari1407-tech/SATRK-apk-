package com.satrk.app

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.content.BroadcastReceiver
import android.content.Context
import android.content.IntentFilter
import android.graphics.Color
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import com.satrk.app.network.CallWebSocketClient
import com.satrk.app.service.CallMonitorService

class MainActivity : AppCompatActivity() {

    private lateinit var etServerIp: EditText
    private lateinit var btnStart: Button
    private lateinit var btnStop: Button
    private lateinit var tvStatus: TextView

    private val statusReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action == CallMonitorService.ACTION_STATUS_UPDATE) {
                val status = intent.getStringExtra(CallMonitorService.EXTRA_STATUS)
                updateStatusUI(status)
            }
        }
    }

    companion object {
        private const val PERMISSION_REQUEST_CODE = 200
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        etServerIp = findViewById(R.id.etServerIp)
        btnStart = findViewById(R.id.btnStart)
        btnStop = findViewById(R.id.btnStop)
        tvStatus = findViewById(R.id.tvStatus)

        btnStart.setOnClickListener {
            if (checkAndRequestPermissions()) {
                startMonitoringService()
            }
        }

        btnStop.setOnClickListener {
            stopMonitoringService()
        }
    }

    override fun onResume() {
        super.onResume()
        val filter = IntentFilter(CallMonitorService.ACTION_STATUS_UPDATE)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(statusReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            registerReceiver(statusReceiver, filter)
        }
    }

    override fun onPause() {
        super.onPause()
        unregisterReceiver(statusReceiver)
    }

    private fun updateStatusUI(status: String?) {
        when (status) {
            CallMonitorService.STATUS_CONNECTED -> {
                tvStatus.text = "Status: Connected"
                tvStatus.setTextColor(Color.parseColor("#10B981")) // Green
            }
            CallMonitorService.STATUS_DISCONNECTED -> {
                tvStatus.text = "Status: Disconnected"
                tvStatus.setTextColor(Color.parseColor("#EF4444")) // Red
            }
            CallMonitorService.STATUS_ERROR -> {
                tvStatus.text = "Status: Error/Disconnected"
                tvStatus.setTextColor(Color.parseColor("#F59E0B")) // Orange
            }
        }
    }

    private fun checkAndRequestPermissions(): Boolean {
        val permissions = mutableListOf(
            Manifest.permission.RECORD_AUDIO,
            Manifest.permission.READ_PHONE_STATE,
            Manifest.permission.INTERNET,
            Manifest.permission.ACCESS_NETWORK_STATE
        )

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            permissions.add(Manifest.permission.FOREGROUND_SERVICE)
        }

        val listPermissionsNeeded = permissions.filter {
            ContextCompat.checkSelfPermission(this, it) != PackageManager.PERMISSION_GRANTED
        }

        if (listPermissionsNeeded.isNotEmpty()) {
            ActivityCompat.requestPermissions(
                this,
                listPermissionsNeeded.toTypedArray(),
                PERMISSION_REQUEST_CODE
            )
            return false
        }
        return true
    }

    private fun startMonitoringService() {
        val rawIp = etServerIp.text.toString()
        val (ip, port) = CallWebSocketClient.parseServerAddress(rawIp, 8000)
        val intent = Intent(this, CallMonitorService::class.java).apply {
            action = CallMonitorService.ACTION_START_MONITORING
            putExtra(CallMonitorService.EXTRA_SERVER_IP, ip)
            putExtra(CallMonitorService.EXTRA_SERVER_PORT, port)
            putExtra(CallMonitorService.EXTRA_CALL_ID, "call_android_${System.currentTimeMillis()}")
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(intent)
        } else {
            startService(intent)
        }
        tvStatus.text = "Status: Connecting..."
        tvStatus.setTextColor(Color.parseColor("#3B82F6")) // Blue
        Toast.makeText(this, "Satrk Protection Connecting to $ip:$port...", Toast.LENGTH_SHORT).show()
    }

    private fun stopMonitoringService() {
        val intent = Intent(this, CallMonitorService::class.java).apply {
            action = CallMonitorService.ACTION_STOP_MONITORING
        }
        startService(intent)
        Toast.makeText(this, "Satrk Call Protection Stopped.", Toast.LENGTH_SHORT).show()
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == PERMISSION_REQUEST_CODE) {
            if (grantResults.isNotEmpty() && grantResults.all { it == PackageManager.PERMISSION_GRANTED }) {
                startMonitoringService()
            } else {
                Toast.makeText(this, "Microphone & Network permissions required for Satrk live call shield.", Toast.LENGTH_LONG).show()
            }
        }
    }
}
