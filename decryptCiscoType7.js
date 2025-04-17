/**
 * La clave XOR constante utilizada por el cifrado Cisco Tipo 7.
 * Asegúrate de que esta constante esté definida en el mismo ámbito
 * o uno superior a donde se llama la función.
 */
const XOR_KEY = "dsfd;kfoA,.iyewrkldJKD;-&]a(%/";

/**
 * Descifra un hash de contraseña Cisco Tipo 7.
 * @param {string} encryptedHash - La cadena hash cifrada Cisco Tipo 7.
 * @returns {string} La contraseña descifrada en texto plano.
 * @throws {Error} Si la entrada es inválida o el descifrado falla
 * (ej: formato incorrecto, índice fuera de rango).
 */
function decryptCiscoType7(encryptedHash) {
    // --- Validación de Entrada ---
    if (typeof encryptedHash !== 'string' || encryptedHash === "") {
        throw new Error("La entrada debe ser una cadena de texto no vacía.");
    }
    const hashLen = encryptedHash.length;
    if (hashLen < 4) {
        throw new Error("El hash cifrado es demasiado corto (mínimo 4 caracteres).");
    }
    if (hashLen % 2 !== 0) {
        throw new Error("El hash cifrado debe tener una longitud par.");
    }

    // --- Extracción y Conversión del Índice Inicial ---
    const startIndexHex = encryptedHash.substring(0, 2);
    // parseInt devuelve NaN en caso de fallo
    const startIndex = parseInt(startIndexHex, 16);
    if (isNaN(startIndex)) {
        throw new Error(`Índice inicial hexadecimal inválido: '${startIndexHex}'.`);
    }
    let currentIndex = startIndex; // Usar let ya que se incrementará

    // --- Bucle de Descifrado ---
    const hexPairsStr = encryptedHash.substring(2);
    let decryptedPassword = ""; // Usar concatenación simple de cadenas

    for (let i = 0; i < hexPairsStr.length; i += 2) {
        // Extraer el par hexadecimal actual
        const hexPair = hexPairsStr.substring(i, i + 2);

        // --- Verificación de Límites del Índice de la Clave ---
        if (currentIndex >= XOR_KEY.length) {
            throw new Error(`Índice calculado (${currentIndex}) fuera de los límites de la clave XOR (longitud ${XOR_KEY.length}).`);
        }

        // --- Obtener Valores para el XOR ---
        // Obtener el código ASCII/Unicode del carácter de la clave
        const keyCharCode = XOR_KEY.charCodeAt(currentIndex);

        // Parsear la cadena del par hexadecimal a un valor entero
        const hexPairValue = parseInt(hexPair, 16);
        if (isNaN(hexPairValue)) {
            // Proveer contexto sobre el par inválido y su posición
            // La posición i+2 corresponde al inicio del par en el hash original
            throw new Error(`Par hexadecimal inválido '${hexPair}' encontrado en la posición ${i + 2}.`);
        }

        // --- Realizar XOR y Añadir Resultado ---
        // Realizar la operación XOR bit a bit
        const decryptedCharCode = keyCharCode ^ hexPairValue;
        // Convertir el código de carácter resultante de nuevo a un carácter y añadirlo
        decryptedPassword += String.fromCharCode(decryptedCharCode);

        // Incrementar el índice para el siguiente carácter en la xorKey
        currentIndex++;
    }

    // Devolver la cadena final con la contraseña descifrada
    return decryptedPassword;
}
