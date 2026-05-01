// Historical pre-v1.0 test suite.
//
// These tests exercise the earlier SHA-256-only construction in
// HID64.java; they do NOT verify v1.0 conformance. Preserved for
// reference. The canonical v1.0 test suite is at
// hid64/tests/python/test_hid64.py.

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class HID64Test {

    // Función de prueba para generar y validar HID64
    @Test
    public void testGenerateHID64() {
        String rootId = "123e4567-e89b-12d3-a456-426614174000";
        long iter1 = HID64.generateHID64(rootId);
        long activity1 = HID64.generateHID64(String.valueOf(iter1));
        long artifact1 = HID64.generateHID64(String.valueOf(activity1));

        // Verificar que los IDs generados sean únicos
        assertNotEquals(iter1, activity1, "Iteration ID should not be equal to Activity ID");
        assertNotEquals(activity1, artifact1, "Activity ID should not be equal to Artifact ID");
        assertNotEquals(iter1, artifact1, "Iteration ID should not be equal to Artifact ID");
    }

    @Test
    public void testValidateHID64() {
        String rootId = "123e4567-e89b-12d3-a456-426614174000";
        long iter1 = HID64.generateHID64(rootId);
        long activity1 = HID64.generateHID64(String.valueOf(iter1));
        long artifact1 = HID64.generateHID64(String.valueOf(activity1));

        // Validación jerárquica correcta
        assertTrue(HID64.validateHID64(rootId, iter1), "Should validate Iteration ID under root");
        assertTrue(HID64.validateHID64(String.valueOf(iter1), activity1), "Should validate Activity ID under Iteration");
        assertTrue(HID64.validateHID64(String.valueOf(activity1), artifact1), "Should validate Artifact ID under Activity");
    }

    @Test
    public void testInvalidHID64() {
        String rootId = "123e4567-e89b-12d3-a456-426614174000";
        long invalidId = HID64.generateHID64("wrong-parent-id");

        // Validación incorrecta
        assertFalse(HID64.validateHID64(rootId, invalidId), "Invalid ID should not validate under the root ID");
    }
}
