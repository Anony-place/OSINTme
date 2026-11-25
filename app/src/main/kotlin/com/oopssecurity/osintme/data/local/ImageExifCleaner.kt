package com.oopssecurity.osintme.data.local

import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.net.Uri
import androidx.core.content.FileProvider
import androidx.exifinterface.media.ExifInterface
import com.oopssecurity.osintme.data.model.ExifMetadata
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileOutputStream
import java.security.MessageDigest

object ImageExifCleaner {

    suspend fun extractMetadata(context: Context, imageUri: Uri): Result<ExifMetadata> = withContext(Dispatchers.IO) {
        try {
            val sha256Hash = computeSha256(context, imageUri)

            val exif = context.contentResolver.openInputStream(imageUri)?.use { inputStream ->
                ExifInterface(inputStream)
            } ?: return@withContext Result.failure(Exception("Unable to open selected image stream."))

            val make = exif.getAttribute(ExifInterface.TAG_MAKE)
            val model = exif.getAttribute(ExifInterface.TAG_MODEL)
            val lensModel = exif.getAttribute(ExifInterface.TAG_LENS_MODEL)
            val software = exif.getAttribute(ExifInterface.TAG_SOFTWARE)
            val dateTime = exif.getAttribute(ExifInterface.TAG_DATETIME_ORIGINAL)
                ?: exif.getAttribute(ExifInterface.TAG_DATETIME)

            var imageWidth = exif.getAttributeInt(ExifInterface.TAG_IMAGE_WIDTH, 0)
            var imageHeight = exif.getAttributeInt(ExifInterface.TAG_IMAGE_LENGTH, 0)

            // Fallback to BitmapFactory bounds if EXIF dimensions are missing (e.g., PNG or stripped JPEG)
            if (imageWidth == 0 || imageHeight == 0) {
                context.contentResolver.openInputStream(imageUri)?.use { stream ->
                    val opts = BitmapFactory.Options().apply { inJustDecodeBounds = true }
                    BitmapFactory.decodeStream(stream, null, opts)
                    if (opts.outWidth > 0 && opts.outHeight > 0) {
                        imageWidth = opts.outWidth
                        imageHeight = opts.outHeight
                    }
                }
            }

            val iso = exif.getAttribute(ExifInterface.TAG_PHOTOGRAPHIC_SENSITIVITY)
            val exposure = exif.getAttribute(ExifInterface.TAG_EXPOSURE_TIME)
            val fNumber = exif.getAttribute(ExifInterface.TAG_F_NUMBER)
            val focalLength = exif.getAttribute(ExifInterface.TAG_FOCAL_LENGTH)

            val latLong = exif.latLong
            val latitude = latLong?.getOrNull(0)
            val longitude = latLong?.getOrNull(1)
            val altitude = exif.getAltitude(Double.NaN).takeIf { !it.isNaN() && it != 0.0 }
            val hasGps = latitude != null && longitude != null

            val fileSize = try {
                context.contentResolver.openFileDescriptor(imageUri, "r")?.use { pfd ->
                    pfd.statSize
                } ?: 0L
            } catch (_: Exception) {
                0L
            }

            Result.success(
                ExifMetadata(
                    make = make,
                    model = model,
                    lensModel = lensModel,
                    software = software,
                    dateTime = dateTime,
                    imageWidth = imageWidth,
                    imageHeight = imageHeight,
                    iso = iso,
                    exposureTime = exposure?.let { formatExposure(it) },
                    fNumber = fNumber?.let { "f/$it" },
                    focalLength = focalLength?.let { "${formatRational(it)}mm" },
                    latitude = latitude,
                    longitude = longitude,
                    altitude = altitude,
                    hasGps = hasGps,
                    originalUri = imageUri.toString(),
                    fileSizeFormatted = formatFileSize(fileSize),
                    sha256Hash = sha256Hash
                )
            )
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    suspend fun stripAndCreateCleanImage(context: Context, imageUri: Uri): Result<Uri> =
        stripAndSaveCleanImage(context, imageUri)

    suspend fun stripAndSaveCleanImage(context: Context, imageUri: Uri): Result<Uri> = withContext(Dispatchers.IO) {
        try {
            val cleanDir = File(context.cacheDir, "clean_images")
            if (!cleanDir.exists()) cleanDir.mkdirs()

            // Purge stale sanitized exports older than 24 hours to minimize local forensic residue
            val cutoffMs = System.currentTimeMillis() - (24L * 60L * 60L * 1000L)
            cleanDir.listFiles()?.forEach { existing ->
                if (existing.isFile && existing.lastModified() < cutoffMs) {
                    runCatching { existing.delete() }
                }
            }

            val cleanFile = File(cleanDir, "sanitized_${System.currentTimeMillis()}.jpg")

            // Decoding via BitmapFactory and re-encoding to JPEG completely discards EXIF, XMP, IPTC, and GPS segments
            val bitmap = context.contentResolver.openInputStream(imageUri)?.use { inputStream ->
                BitmapFactory.decodeStream(inputStream)
            } ?: return@withContext Result.failure(Exception("Failed to decode source image."))

            try {
                FileOutputStream(cleanFile).use { outStream ->
                    bitmap.compress(Bitmap.CompressFormat.JPEG, 95, outStream)
                    outStream.flush()
                }
            } finally {
                bitmap.recycle()
            }

            // Do NOT inject any software watermark or fake (0.0, 0.0) GPS coordinates into the clean output file.
            val shareUri = FileProvider.getUriForFile(
                context,
                "com.oopssecurity.osintme.fileprovider",
                cleanFile
            )

            Result.success(shareUri)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    private fun computeSha256(context: Context, imageUri: Uri): String {
        return try {
            val digest = MessageDigest.getInstance("SHA-256")
            context.contentResolver.openInputStream(imageUri)?.use { stream ->
                val buffer = ByteArray(8192)
                var read = stream.read(buffer)
                while (read != -1) {
                    digest.update(buffer, 0, read)
                    read = stream.read(buffer)
                }
            } ?: return ""
            digest.digest().joinToString("") { "%02x".format(it) }
        } catch (_: Exception) {
            ""
        }
    }

    private fun formatFileSize(bytes: Long): String {
        return when {
            bytes >= 1024 * 1024 -> String.format("%.2f MB", bytes.toDouble() / (1024 * 1024))
            bytes >= 1024 -> String.format("%.1f KB", bytes.toDouble() / 1024)
            bytes > 0 -> "$bytes Bytes"
            else -> "Unknown size"
        }
    }

    private fun formatExposure(exposureStr: String): String {
        val d = exposureStr.toDoubleOrNull() ?: return exposureStr
        return if (d < 1.0 && d > 0.0) {
            val denom = (1.0 / d).toInt().coerceAtLeast(1)
            "1/$denom s"
        } else {
            "${exposureStr}s"
        }
    }

    private fun formatRational(value: String): String {
        if (!value.contains("/")) return value
        val parts = value.split("/")
        val num = parts.getOrNull(0)?.toDoubleOrNull() ?: return value
        val den = parts.getOrNull(1)?.toDoubleOrNull() ?: return value
        if (den == 0.0) return value
        val computed = num / den
        return if (computed % 1.0 == 0.0) computed.toInt().toString() else String.format("%.1f", computed)
    }
}
