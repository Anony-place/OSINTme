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
import java.io.InputStream

object ImageExifCleaner {

    suspend fun extractMetadata(context: Context, imageUri: Uri): Result<ExifMetadata> = withContext(Dispatchers.IO) {
        try {
            var inputStream: InputStream? = null
            try {
                inputStream = context.contentResolver.openInputStream(imageUri)
                    ?: return@withContext Result.failure(Exception("Unable to open image stream"))

                val exif = ExifInterface(inputStream)

                val make = exif.getAttribute(ExifInterface.TAG_MAKE)
                val model = exif.getAttribute(ExifInterface.TAG_MODEL)
                val software = exif.getAttribute(ExifInterface.TAG_SOFTWARE)
                val dateTime = exif.getAttribute(ExifInterface.TAG_DATETIME_ORIGINAL)
                    ?: exif.getAttribute(ExifInterface.TAG_DATETIME)

                val imageWidth = exif.getAttributeInt(ExifInterface.TAG_IMAGE_WIDTH, 0)
                val imageHeight = exif.getAttributeInt(ExifInterface.TAG_IMAGE_LENGTH, 0)

                val iso = exif.getAttribute(ExifInterface.TAG_PHOTOGRAPHIC_SENSITIVITY)
                val exposure = exif.getAttribute(ExifInterface.TAG_EXPOSURE_TIME)
                val fNumber = exif.getAttribute(ExifInterface.TAG_F_NUMBER)
                val focalLength = exif.getAttribute(ExifInterface.TAG_FOCAL_LENGTH)

                val latLong = exif.latLong
                val latitude = latLong?.getOrNull(0)
                val longitude = latLong?.getOrNull(1)
                val altitude = exif.getAltitude(0.0).takeIf { it != 0.0 }
                val hasGps = latitude != null && longitude != null

                // File size estimate safely
                val fileSize = try {
                    val pfd = context.contentResolver.openFileDescriptor(imageUri, "r")
                    val size = pfd?.statSize ?: 0L
                    pfd?.close()
                    size
                } catch (e: Exception) {
                    0L
                }
                val sizeFormatted = formatFileSize(fileSize)

                Result.success(
                    ExifMetadata(
                        make = make,
                        model = model,
                        software = software,
                        dateTime = dateTime,
                        imageWidth = imageWidth,
                        imageHeight = imageHeight,
                        iso = iso,
                        exposureTime = exposure?.let { formatExposure(it) },
                        fNumber = fNumber?.let { "f/$it" },
                        focalLength = focalLength?.let { "${it}mm" },
                        latitude = latitude,
                        longitude = longitude,
                        altitude = altitude,
                        hasGps = hasGps,
                        originalUri = imageUri.toString(),
                        fileSizeFormatted = sizeFormatted
                    )
                )
            } finally {
                inputStream?.close()
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    suspend fun stripAndCreateCleanImage(context: Context, imageUri: Uri): Result<Uri> = stripAndSaveCleanImage(context, imageUri)

    suspend fun stripAndSaveCleanImage(context: Context, imageUri: Uri): Result<Uri> = withContext(Dispatchers.IO) {
        try {
            val cleanDir = File(context.cacheDir, "clean_images")
            if (!cleanDir.exists()) cleanDir.mkdirs()

            val cleanFile = File(cleanDir, "clean_${System.currentTimeMillis()}.jpg")

            // Decode image stream into Bitmap (which discards EXIF tags), recompress to JPEG
            val inputStream = context.contentResolver.openInputStream(imageUri)
                ?: return@withContext Result.failure(Exception("Cannot read source image"))

            val bitmap = BitmapFactory.decodeStream(inputStream)
            inputStream.close()

            if (bitmap == null) {
                return@withContext Result.failure(Exception("Failed to decode image data"))
            }

            val outStream = FileOutputStream(cleanFile)
            bitmap.compress(Bitmap.CompressFormat.JPEG, 95, outStream)
            outStream.flush()
            outStream.close()
            bitmap.recycle()

            // Verify clean EXIF
            val cleanExif = ExifInterface(cleanFile.absolutePath)
            cleanExif.setAttribute(ExifInterface.TAG_MAKE, null)
            cleanExif.setAttribute(ExifInterface.TAG_MODEL, null)
            cleanExif.setAttribute(ExifInterface.TAG_SOFTWARE, "OSINTme Privacy Stripper")
            cleanExif.setLatLong(0.0, 0.0)
            cleanExif.setAttribute(ExifInterface.TAG_GPS_LATITUDE, null)
            cleanExif.setAttribute(ExifInterface.TAG_GPS_LONGITUDE, null)
            cleanExif.setAttribute(ExifInterface.TAG_GPS_ALTITUDE, null)
            cleanExif.saveAttributes()

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
            val denom = (1.0 / d).toInt()
            "1/$denom s"
        } else {
            "${exposureStr}s"
        }
    }
}
