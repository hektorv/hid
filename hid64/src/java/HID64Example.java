// Historical pre-v1.0 example.
//
// This example exercises the earlier SHA-256-only construction in
// HID64.java; it does NOT match the v1.0 normative protocol
// (HMAC-SHA256(secret, "root_id:parent_id") with HKDF-derived
// per-tenant keys). Preserved for reference. The canonical v1.0
// example is hid64/src/python/python_example.py.

import java.util.UUID;

public class HID64Example {

    public static void main(String[] args) {
        // Generar un UUID raíz
        UUID rootUUID = UUID.randomUUID();
        String rootId = rootUUID.toString();

        // Generar identificadores jerárquicos
        long iter1 = HID64.generateHID64(rootId);
        long activity1 = HID64.generateHID64(Long.toString(iter1));
        long artifact1 = HID64.generateHID64(Long.toString(activity1));

        // Mostrar los identificadores generados
        System.out.println("Root UUID:      " + rootId);
        System.out.println("Iteration ID:   " + iter1);
        System.out.println("Activity ID:    " + activity1);
        System.out.println("Artifact ID:    " + artifact1);

        // Validaciones de la jerarquía
        System.out.println("\nValidations:");
        System.out.println("Iteration ← root?     " + HID64.validateHID64(rootId, iter1));        // true
        System.out.println("Activity ← iter1?     " + HID64.validateHID64(Long.toString(iter1), activity1)); // true
        System.out.println("Artifact ← activity1? " + HID64.validateHID64(Long.toString(activity1), artifact1)); // true
    }
}
