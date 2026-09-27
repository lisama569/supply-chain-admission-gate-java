package com.github.lisama569.supplychainadmissiongatejava.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.lisama569.supplychainadmissiongatejava.common.GateException;
import com.github.lisama569.supplychainadmissiongatejava.common.RejectionReason;
import com.github.lisama569.supplychainadmissiongatejava.model.ArtifactRecord;
import com.github.lisama569.supplychainadmissiongatejava.support.GateTestFixtures;
import java.nio.file.Path;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * 多格式导入与拒绝原因可区分性测试。
 */
class ImportRejectionTest {

    private GateTestFixtures fx;

    @BeforeEach
    void setUp(@TempDir Path tempDir) {
        fx = new GateTestFixtures(tempDir);
    }

    @Test
    void importsAllThreeSupportedFormatsAndNormalizes() {
        ArtifactRecord spdx = fx.importService.importManifest(GateTestFixtures.analyst(),
                "req-spdx-1", "spdx",
                GateTestFixtures.sample("valid", "spdx-2.3.json"),
                GateTestFixtures.signature("valid", "spdx-2.3.json"));
        assertEquals("payments-service@4.2.0", spdx.artifactKey());
        assertEquals("spdx", spdx.manifest().format());
        assertEquals(2, spdx.manifest().components().size());
        assertEquals(2, spdx.manifest().declaredVulns().size());
        System.out.println("[输入摘要] SPDX 导入成功 key=" + spdx.artifactKey()
                + " digest=" + spdx.digestHex());

        ArtifactRecord cdx = fx.importService.importManifest(GateTestFixtures.analyst(),
                "req-cdx-1", "cyclonedx",
                GateTestFixtures.sample("valid", "cyclonedx-1.5.json"),
                GateTestFixtures.signature("valid", "cyclonedx-1.5.json"));
        assertEquals("edge-gateway@7.0.1", cdx.artifactKey());
        assertEquals("cyclonedx", cdx.manifest().format());

        ArtifactRecord internal = fx.importService.importManifest(GateTestFixtures.analyst(),
                "req-int-1", "internal",
                GateTestFixtures.sample("valid", "manifest-v1.json"),
                GateTestFixtures.signature("valid", "manifest-v1.json"));
        assertEquals("billing-core@2.5.0", internal.artifactKey());
        assertEquals("internal", internal.manifest().format());
    }

    @Test
    void invalidSignatureIsRejectedNotSilentlyAccepted() {
        GateException ex = assertThrows(GateException.class,
                () -> fx.importService.importManifest(GateTestFixtures.analyst(),
                        "req-bad-sig", "spdx",
                        GateTestFixtures.sample("invalid", "spdx-bad-signature.json"),
                        GateTestFixtures.signature("invalid", "spdx-bad-signature.json")));
        assertEquals(RejectionReason.INVALID_SIGNATURE, ex.reason());
        System.out.println("[拒绝原因] INVALID_SIGNATURE -> " + ex.getMessage());
    }

    @Test
    void missingSignatureIsRejected() {
        GateException ex = assertThrows(GateException.class,
                () -> fx.importService.importManifest(GateTestFixtures.analyst(),
                        "req-no-sig", "spdx",
                        GateTestFixtures.sample("valid", "spdx-2.3.json"), "  "));
        assertEquals(RejectionReason.MISSING_SIGNATURE, ex.reason());
    }

    @Test
    void incompatibleVersionsAreRejectedForEachFormat() {
        assertVersionRejected("spdx", "spdx-bad-version.json");
        assertVersionRejected("cyclonedx", "cyclonedx-bad-version.json");
        assertVersionRejected("internal", "manifest-bad-version.json");
    }

    private void assertVersionRejected(String format, String file) {
        GateException ex = assertThrows(GateException.class,
                () -> fx.importService.importManifest(GateTestFixtures.analyst(),
                        "req-version-" + file, format,
                        GateTestFixtures.sample("invalid", file),
                        GateTestFixtures.signature("invalid", file)));
        assertEquals(RejectionReason.INCOMPATIBLE_VERSION, ex.reason());
        System.out.println("[拒绝原因] INCOMPATIBLE_VERSION (" + format + ") -> " + ex.getMessage());
    }

    @Test
    void missingFieldsAreRejected() {
        GateException ex = assertThrows(GateException.class,
                () -> fx.importService.importManifest(GateTestFixtures.analyst(),
                        "req-missing", "spdx",
                        GateTestFixtures.sample("invalid", "spdx-missing-fields.json"),
                        GateTestFixtures.signature("invalid", "spdx-missing-fields.json")));
        assertEquals(RejectionReason.MISSING_FIELD, ex.reason());
    }

    @Test
    void unsupportedDigestAlgorithmIsRejected() {
        GateException ex = assertThrows(GateException.class,
                () -> fx.importService.importManifest(GateTestFixtures.analyst(),
                        "req-md5", "spdx",
                        GateTestFixtures.sample("invalid", "spdx-md5-algorithm.json"),
                        GateTestFixtures.signature("invalid", "spdx-md5-algorithm.json")));
        assertEquals(RejectionReason.UNSUPPORTED_ALGORITHM, ex.reason());
    }

    @Test
    void malformedJsonIsRejected() {
        GateException ex = assertThrows(GateException.class,
                () -> fx.importService.importManifest(GateTestFixtures.analyst(),
                        "req-broken", "spdx",
                        GateTestFixtures.sample("invalid", "broken.json"),
                        GateTestFixtures.signature("invalid", "broken.json")));
        assertEquals(RejectionReason.MALFORMED_DOCUMENT, ex.reason());
    }

    @Test
    void unknownFormatIsRejected() {
        GateException ex = assertThrows(GateException.class,
                () -> fx.importService.importManifest(GateTestFixtures.analyst(),
                        "req-unknown", "swid",
                        GateTestFixtures.sample("valid", "spdx-2.3.json"),
                        GateTestFixtures.signature("valid", "spdx-2.3.json")));
        assertEquals(RejectionReason.UNSUPPORTED_FORMAT, ex.reason());
        assertTrue(ex.getMessage().contains("spdx"));
    }

    @Test
    void provenanceRejectionsAreDistinguishable() {
        fx.importService.importManifest(GateTestFixtures.analyst(),
                "req-base-internal", "internal",
                GateTestFixtures.sample("valid", "manifest-v1.json"),
                GateTestFixtures.signature("valid", "manifest-v1.json"));

        GateException badVersion = assertThrows(GateException.class,
                () -> fx.importService.attachProvenance(GateTestFixtures.analyst(),
                        "req-prov-version", "billing-core@2.5.0",
                        GateTestFixtures.sample("invalid", "provenance-bad-version-v1.json"),
                        GateTestFixtures.signature("invalid", "provenance-bad-version-v1.json")));
        assertEquals(RejectionReason.INCOMPATIBLE_VERSION, badVersion.reason());

        GateException digestMismatch = assertThrows(GateException.class,
                () -> fx.importService.attachProvenance(GateTestFixtures.analyst(),
                        "req-prov-digest", "billing-core@2.5.0",
                        GateTestFixtures.sample("invalid", "provenance-digest-mismatch-v1.json"),
                        GateTestFixtures.signature("invalid", "provenance-digest-mismatch-v1.json")));
        assertEquals(RejectionReason.PROVENANCE_MISMATCH, digestMismatch.reason());

        GateException conflicting = assertThrows(GateException.class,
                () -> fx.importService.attachProvenance(GateTestFixtures.analyst(),
                        "req-prov-conflict", "billing-core@2.5.0",
                        GateTestFixtures.sample("invalid", "provenance-conflicting-source-v1.json"),
                        GateTestFixtures.signature("invalid", "provenance-conflicting-source-v1.json")));
        assertEquals(RejectionReason.INCONSISTENT_SOURCE, conflicting.reason());
        System.out.println("[拒绝原因] INCONSISTENT_SOURCE -> " + conflicting.getMessage());
    }

    @Test
    void provenanceForUnknownArtifactIsRejectedAsNotFound() {
        GateException ex = assertThrows(GateException.class,
                () -> fx.importService.attachProvenance(GateTestFixtures.analyst(),
                        "req-prov-ghost", "ghost@9.9.9",
                        GateTestFixtures.sample("valid", "provenance-cyclonedx-v1.json"),
                        GateTestFixtures.signature("valid", "provenance-cyclonedx-v1.json")));
        assertEquals(RejectionReason.NOT_FOUND, ex.reason());
    }

    @Test
    void provenanceWithoutSignatureIsRejected() {
        fx.importService.importManifest(GateTestFixtures.analyst(),
                "req-base-cdx", "cyclonedx",
                GateTestFixtures.sample("valid", "cyclonedx-1.5.json"),
                GateTestFixtures.signature("valid", "cyclonedx-1.5.json"));
        GateException ex = assertThrows(GateException.class,
                () -> fx.importService.attachProvenance(GateTestFixtures.analyst(),
                        "req-prov-nosig", "edge-gateway@7.0.1",
                        GateTestFixtures.sample("valid", "provenance-cyclonedx-v1.json"), null));
        assertEquals(RejectionReason.MISSING_SIGNATURE, ex.reason());
    }
}
