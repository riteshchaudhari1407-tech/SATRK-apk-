package com.satark.app

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import com.satark.app.network.CallWebSocketClient
import com.satark.app.service.CallMonitorService

class MainActivity : AppCompatActivity() {

    private lateinit var etServerIp: EditText
    private lateinit var btnStart: Button
    private lateinit var btnStop: Button

    companion object {
        private const val PERMISSION_REQUEST_CODE = 200
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate()
        setContentView(R.layout.activity_main)

        etServerIp = findViewById(R.id.etServerIp)
        btnStart = findViewById(R.id.btnStart)
        btnStop = findViewById(R.id.btnStop)

        btnStart.setOnClickListener {
            if (checkAndRequestPermissions()) {
                startMonitoringService()
            }
        }

        btnStop.setOnClickListener {
            stopMonitoringService()
        }
    }

    private fun checkAndRequestPermissions(): Boolean {
        val permissions = mutableListOf(
            Manifest.permission.RECORD_AUDIO,
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
        val ip = etServerIp.text.toString().ifBlank { CallWebSocketClient.DEFAULT_SERVER_IP }
        val intent = Intent(this, CallMonitorService::class.java).apply {
            action = CallMonitorService.ACTION_START_MONITORING
            putExtra(CallMonitorService.EXTRA_SERVER_IP, ip)
            putExtra(CallMonitorService.EXTRA_SERVER_PORT, 8000)
            putExtra(CallMonitorService.EXTRA_CALL_ID, "call_android_${System.currentTimeMillis()}")
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(intent)
        } else {
            startService(intent)
        }
        Toast.makeText(this, "Satark Call Protection Started!", Toast.LENGTH_SHORT).show()
    }

    private fun stopMonitoringService() {
        val intent = Intent(this, CallMonitorService::class.java).apply {
            action = CallMonitorService.ACTION_STOP_MONITORING
        }
        startService(intent)
        Toast.makeText(this, "Satark Call Protection Stopped.", Toast.LENGTH_SHORT).show()
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
                Toast.makeText(this, "Microphone & Network permissions required for Satark live call shield.", Toast.LENGTH_LONG).show()
            }
        }
    }
}
