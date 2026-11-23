package com.oopssecurity.osintme.data.local

import android.content.Context
import android.content.SharedPreferences
import com.oopssecurity.osintme.data.model.ScanHistoryItem
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.json.JSONArray
import org.json.JSONObject
import java.util.UUID

class LocalScanHistoryManager(context: Context) {
    private val prefs: SharedPreferences = context.getSharedPreferences("osintme_private_history", Context.MODE_PRIVATE)
    private val _historyFlow = MutableStateFlow<List<ScanHistoryItem>>(loadHistory())
    val historyFlow: StateFlow<List<ScanHistoryItem>> = _historyFlow.asStateFlow()

    private fun loadHistory(): List<ScanHistoryItem> {
        val raw = prefs.getString("scans", null) ?: return emptyList()
        val list = mutableListOf<ScanHistoryItem>()
        try {
            val array = JSONArray(raw)
            for (i in 0 until array.length()) {
                val obj = array.getJSONObject(i)
                list.add(
                    ScanHistoryItem(
                        id = obj.optString("id", UUID.randomUUID().toString()),
                        type = obj.optString("type", ""),
                        target = obj.optString("target", ""),
                        summary = obj.optString("summary", ""),
                        timestamp = obj.optLong("timestamp", System.currentTimeMillis())
                    )
                )
            }
        } catch (e: Exception) {
            // Ignore corrupted history
        }
        return list.sortedByDescending { it.timestamp }
    }

    fun addScan(type: String, target: String, summary: String) {
        val current = _historyFlow.value.toMutableList()
        val newItem = ScanHistoryItem(
            id = UUID.randomUUID().toString(),
            type = type,
            target = target,
            summary = summary,
            timestamp = System.currentTimeMillis()
        )
        // Keep max 50 recent scans locally
        current.add(0, newItem)
        if (current.size > 50) {
            current.removeAt(current.lastIndex)
        }
        saveHistory(current)
    }

    fun deleteScan(id: String) {
        val current = _historyFlow.value.filter { it.id != id }
        saveHistory(current)
    }

    fun clearHistory() {
        prefs.edit().remove("scans").apply()
        _historyFlow.value = emptyList()
    }

    private fun saveHistory(list: List<ScanHistoryItem>) {
        val array = JSONArray()
        for (item in list) {
            val obj = JSONObject().apply {
                put("id", item.id)
                put("type", item.type)
                put("target", item.target)
                put("summary", item.summary)
                put("timestamp", item.timestamp)
            }
            array.put(obj)
        }
        prefs.edit().putString("scans", array.toString()).apply()
        _historyFlow.value = list
    }
}
