package com.oopssecurity.osintme.data.local.case

import android.content.ContentValues
import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import com.oopssecurity.osintme.data.model.InvestigationCase
import com.oopssecurity.osintme.data.model.ScanArtifact
import java.util.UUID

class CaseDatabaseHelper(context: Context) : SQLiteOpenHelper(context, DATABASE_NAME, null, DATABASE_VERSION) {

    companion object {
        const val DATABASE_NAME = "osintme_cases.db"
        const val DATABASE_VERSION = 1

        const val TABLE_CASES = "cases"
        const val TABLE_ARTIFACTS = "artifacts"
    }

    override fun onCreate(db: SQLiteDatabase) {
        val createCasesSql = """
            CREATE TABLE $TABLE_CASES (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                target TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                notes TEXT,
                tags TEXT,
                status TEXT NOT NULL DEFAULT 'ACTIVE'
            )
        """.trimIndent()

        val createArtifactsSql = """
            CREATE TABLE $TABLE_ARTIFACTS (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                wing_type TEXT NOT NULL,
                artifact_type TEXT NOT NULL,
                query_target TEXT NOT NULL,
                title TEXT NOT NULL,
                summary TEXT NOT NULL,
                raw_json TEXT NOT NULL,
                confidence TEXT NOT NULL DEFAULT 'HIGH',
                source_api TEXT,
                timestamp INTEGER NOT NULL,
                FOREIGN KEY(case_id) REFERENCES $TABLE_CASES(id) ON DELETE CASCADE
            )
        """.trimIndent()

        db.execSQL(createCasesSql)
        db.execSQL(createArtifactsSql)
        db.execSQL("CREATE INDEX idx_artifacts_case_id ON $TABLE_ARTIFACTS(case_id)")
    }

    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
        db.execSQL("DROP TABLE IF EXISTS $TABLE_ARTIFACTS")
        db.execSQL("DROP TABLE IF EXISTS $TABLE_CASES")
        onCreate(db)
    }

    override fun onConfigure(db: SQLiteDatabase) {
        super.onConfigure(db)
        db.setForeignKeyConstraintsEnabled(true)
    }
}
