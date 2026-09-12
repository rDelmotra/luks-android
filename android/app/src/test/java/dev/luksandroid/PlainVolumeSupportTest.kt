package dev.luksandroid

import android.content.ContextWrapper
import dev.luksandroid.session.SessionController
import dev.luksandroid.session.SessionState
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class PlainVolumeSupportTest {

    private lateinit var testScope: CoroutineScope
    private lateinit var session: SessionController

    @Before
    fun setUp() {
        testScope = CoroutineScope(Dispatchers.Default + SupervisorJob())
        session = SessionController(scope = testScope)
    }

    @After
    fun tearDown() {
        testScope.cancel()
    }

    @Test
    fun testPartitionInfoProperties() {
        // LUKS partition
        val luksPart = PartitionInfo(
            index = 1,
            name = "cryptdata",
            offsetBytes = 1048576L,
            sizeBytes = 1073741824L,
            isLuks = true,
            luksVersion = 2,
            fsType = null,
            unsupportedReason = null,
        )
        assertFalse(luksPart.isPlain)
        assertTrue(luksPart.isOpenable)
        assertTrue(luksPart.label.contains("LUKS2"))

        // Plain ext4 partition
        val ext4Part = PartitionInfo(
            index = 2,
            name = "linux-data",
            offsetBytes = 2097152L,
            sizeBytes = 2147483648L,
            isLuks = false,
            luksVersion = null,
            fsType = "ext4",
            unsupportedReason = null,
        )
        assertTrue(ext4Part.isPlain)
        assertTrue(ext4Part.isOpenable)
        assertTrue(ext4Part.label.contains("EXT4"))

        // Plain btrfs partition
        val btrfsPart = PartitionInfo(
            index = 3,
            name = "pool",
            offsetBytes = 3145728L,
            sizeBytes = 4294967296L,
            isLuks = false,
            luksVersion = null,
            fsType = "btrfs",
            unsupportedReason = null,
        )
        assertTrue(btrfsPart.isPlain)
        assertTrue(btrfsPart.isOpenable)
        assertTrue(btrfsPart.label.contains("BTRFS"))

        // Plain unsupported filesystem (e.g. FAT32)
        val fatPart = PartitionInfo(
            index = 4,
            name = "usb-stick",
            offsetBytes = 4194304L,
            sizeBytes = 536870912L,
            isLuks = false,
            luksVersion = null,
            fsType = "FAT32",
            unsupportedReason = "FAT32 is not supported yet",
        )
        assertFalse(fatPart.isPlain)
        assertFalse(fatPart.isOpenable)
        assertTrue(fatPart.label.contains("FAT32 (Unsupported)"))

        // Unknown / unformatted partition
        val unknownPart = PartitionInfo(
            index = 5,
            name = "raw",
            offsetBytes = 5242880L,
            sizeBytes = 104857600L,
            isLuks = false,
            luksVersion = null,
            fsType = null,
            unsupportedReason = null,
        )
        assertFalse(unknownPart.isPlain)
        assertFalse(unknownPart.isOpenable)
    }

    @Test
    fun testParseDeviceInfoWithPlainAndUnsupportedPartitions() {
        val json = """
            {
                "vendor": "Generic",
                "product": "Flash Disk",
                "blockSize": 512,
                "sizeBytes": 8589934592,
                "tableKind": "GPT",
                "partitions": [
                    {
                        "index": 1,
                        "name": "luks-part",
                        "offsetBytes": 1048576,
                        "sizeBytes": 1073741824,
                        "isLuks": true,
                        "luksVersion": 2,
                        "typeGuid": "0fc63daf-8483-4772-8e79-3d69d8477de4",
                        "mbrType": null,
                        "fsType": null,
                        "unsupportedReason": null
                    },
                    {
                        "index": 2,
                        "name": "plain-ext4",
                        "offsetBytes": 1074790400,
                        "sizeBytes": 2147483648,
                        "isLuks": false,
                        "luksVersion": null,
                        "typeGuid": "0fc63daf-8483-4772-8e79-3d69d8477de4",
                        "mbrType": null,
                        "fsType": "ext4",
                        "unsupportedReason": null
                    },
                    {
                        "index": 3,
                        "name": "plain-fat32",
                        "offsetBytes": 3222274048,
                        "sizeBytes": 1073741824,
                        "isLuks": false,
                        "luksVersion": null,
                        "typeGuid": "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7",
                        "mbrType": null,
                        "fsType": "FAT32",
                        "unsupportedReason": "FAT32 is not supported yet"
                    }
                ]
            }
        """.trimIndent()

        val deviceInfo = parseDeviceInfo(json)
        assertEquals("Generic", deviceInfo.vendor)
        assertEquals("Flash Disk", deviceInfo.product)
        assertEquals(3, deviceInfo.partitions.size)

        val p1 = deviceInfo.partitions[0]
        assertTrue(p1.isLuks)
        assertFalse(p1.isPlain)
        assertTrue(p1.isOpenable)
        assertNull(p1.fsType)
        assertNull(p1.unsupportedReason)

        val p2 = deviceInfo.partitions[1]
        assertFalse(p2.isLuks)
        assertTrue(p2.isPlain)
        assertTrue(p2.isOpenable)
        assertEquals("ext4", p2.fsType)
        assertNull(p2.unsupportedReason)

        val p3 = deviceInfo.partitions[2]
        assertFalse(p3.isLuks)
        assertFalse(p3.isPlain)
        assertFalse(p3.isOpenable)
        assertEquals("FAT32", p3.fsType)
        assertEquals("FAT32 is not supported yet", p3.unsupportedReason)
    }

    @Test
    fun testParseVolumeInfoEncryptedField() {
        val plainJson = """
            {
                "label": "MyDrive",
                "uuid": "1234-5678",
                "blockSize": 4096,
                "sizeBytes": 1073741824,
                "fsType": "ext4",
                "subvolumes": [],
                "encrypted": false
            }
        """.trimIndent()
        val plainVol = parseVolumeInfo(plainJson)
        assertEquals("MyDrive", plainVol.label)
        assertEquals("ext4", plainVol.fsType)
        assertFalse(plainVol.encrypted)

        val encryptedJson = """
            {
                "label": "SecureDrive",
                "uuid": "8765-4321",
                "blockSize": 4096,
                "sizeBytes": 1073741824,
                "fsType": "btrfs",
                "subvolumes": [],
                "encrypted": true
            }
        """.trimIndent()
        val encVol = parseVolumeInfo(encryptedJson)
        assertTrue(encVol.encrypted)

        // Default when absent must be true
        val defaultJson = """
            {
                "label": "LegacyDrive",
                "uuid": "1111-2222",
                "blockSize": 4096,
                "sizeBytes": 1073741824,
                "fsType": "ext4",
                "subvolumes": []
            }
        """.trimIndent()
        val defVol = parseVolumeInfo(defaultJson)
        assertTrue(defVol.encrypted)
    }

    @Test
    fun testOpenablePartitionsFilter() {
        val p1 = PartitionInfo(1, "luks", 100L, 1000L, isLuks = true, luksVersion = 2)
        val p2 = PartitionInfo(2, "ext4", 200L, 1000L, isLuks = false, luksVersion = null, fsType = "ext4")
        val p3 = PartitionInfo(3, "fat32", 300L, 1000L, isLuks = false, luksVersion = null, fsType = "FAT32", unsupportedReason = "FAT32 is not supported yet")
        val p4 = PartitionInfo(4, "raw", 400L, 1000L, isLuks = false, luksVersion = null, fsType = null)

        val dev = object : LuksDevice(0L) {
            override val info = DeviceInfo(
                vendor = "Test",
                product = "Drive",
                blockSize = 512,
                sizeBytes = 10000L,
                tableKind = "GPT",
                partitions = listOf(p1, p2, p3, p4),
                writeProbe = null,
            )
        }

        assertEquals(listOf(p1), dev.luksPartitions)
        assertEquals(listOf(p1, p2), dev.openablePartitions)
    }

    @Test
    fun testLuksSessionOpenPlainSuccess() = runBlocking {
        val partition = PartitionInfo(
            index = 1,
            name = "plain-data",
            offsetBytes = 1048576L,
            sizeBytes = 1073741824L,
            isLuks = false,
            luksVersion = null,
            fsType = "ext4",
        )

        val fakeVol = object : LuksVolume(0L) {
            override val info = VolumeInfo(
                label = "plain-ext4",
                uuid = "abcd-1234",
                blockSize = 4096,
                sizeBytes = 1073741824L,
                fsType = "ext4",
                subvolumes = emptyList(),
                encrypted = false,
            )

            override fun listDir(path: String): List<Entry> {
                return listOf(Entry("hello.txt", "file", size = 12L))
            }
        }

        val fakeDev = object : LuksDevice(0L) {
            override val info = DeviceInfo(
                vendor = "USB",
                product = "Drive",
                blockSize = 512,
                sizeBytes = 2147483648L,
                tableKind = "GPT",
                partitions = listOf(partition),
                writeProbe = null,
            )

            override fun openPlain(partitionOffset: Long): LuksVolume {
                assertEquals(partition.offsetBytes, partitionOffset)
                return fakeVol
            }
        }

        val context = ContextWrapper(null)
        val result = session.openPlain(context, fakeDev, partition)

        assertTrue("Expected SessionState.Unlocked, got $result", result is SessionState.Unlocked)
        val unlocked = result as SessionState.Unlocked
        assertEquals(partition, unlocked.partition)
        assertEquals(1, unlocked.entries.size)
        assertEquals("hello.txt", unlocked.entries[0].name)
        assertFalse(unlocked.volume.info.encrypted)

        // Verify session lease works
        val count = session.withLease { vol ->
            vol.listDir("/").size
        }
        assertEquals(1, count)
    }

    @Test
    fun testLuksSessionOpenPlainFailure() = runBlocking {
        val partition = PartitionInfo(
            index = 1,
            name = "plain-data",
            offsetBytes = 1048576L,
            sizeBytes = 1073741824L,
            isLuks = false,
            luksVersion = null,
            fsType = "ext4",
        )

        val fakeDev = object : LuksDevice(0L) {
            override val info = DeviceInfo(
                vendor = "USB",
                product = "Drive",
                blockSize = 512,
                sizeBytes = 2147483648L,
                tableKind = "GPT",
                partitions = listOf(partition),
                writeProbe = null,
            )

            override fun openPlain(partitionOffset: Long): LuksVolume {
                throw LuksException("cannot open plain partition", LuksException.CORRUPT)
            }
        }

        val context = ContextWrapper(null)
        val result = session.openPlain(context, fakeDev, partition)

        assertTrue("Expected SessionState.Failed, got $result", result is SessionState.Failed)
        val failed = result as SessionState.Failed
        assertEquals(partition, failed.partition)
        assertTrue(failed.message.contains(LuksException.CORRUPT.toString()))
    }
}
