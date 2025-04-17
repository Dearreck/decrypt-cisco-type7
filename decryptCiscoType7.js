document.addEventListener('DOMContentLoaded', () => {
    const decodeForm = document.getElementById('decodeForm');
    const type7Input = document.getElementById('type7Input');
    const resultOutput = document.getElementById('resultOutput');

    // La clave de Vigenere utilizada por Cisco Type 7 (conocida públicamente)
    // const XOR_KEY = "dsfd;kfoA,.iyewrkldJKD;-&]a(%/";
    const vigenereKey = [
        0x64, 0x73, 0x66, 0x64, 0x3b, 0x6b, 0x66, 0x6f, 0x41, 0x2c, 0x2e,
        0x69, 0x79, 0x65, 0x77, 0x72, 0x6b, 0x6c, 0x64, 0x4a, 0x4b, 0x44,
        0x48, 0x53, 0x55, 0x42, 0x73, 0x67, 0x76, 0x63, 0x61, 0x36, 0x39,
        0x38, 0x33, 0x34, 0x6e, 0x63, 0x78, 0x76, 0x39, 0x38, 0x37, 0x33,
        0x32, 0x35, 0x34, 0x6b, 0x66, 0x67, 0x38, 0x37
    ];

    // Función para decodificar la contraseña Type 7
    function decodeType7(encrypted) {
        // Validar formato básico (longitud mínima y caracteres hexadecimales)
        if (!encrypted || encrypted.length < 4 || !/^[0-9a-fA-F]+$/.test(encrypted)) {
             // Podríamos ser más específicos, pero esto cubre la mayoría de errores iniciales
             // Si la longitud es impar después de los dos primeros caracteres, también es inválido
             if (encrypted && encrypted.length > 2 && (encrypted.length - 2) % 2 !== 0) {
                return 'Error: Longitud de la parte cifrada inválida (debe ser par).';
             }
            return 'Error: Formato de contraseña Type 7 inválido.';
        }

        try {
            // El primer par de caracteres hexadecimales indica el índice inicial en la clave Vigenere
            const startIndexHex = encrypted.substring(0, 2);
            let startIndex = parseInt(startIndexHex, 16);

            if (isNaN(startIndex) || startIndex < 0 || startIndex >= vigenereKey.length) {
                 return `Error: Índice inicial inválido (${startIndexHex}).`;
            }

            let decrypted = '';
            // Recorre el resto de la cadena cifrada en pares de caracteres hexadecimales
            for (let i = 2; i < encrypted.length; i += 2) {
                // Obtiene el par hexadecimal
                const hexPair = encrypted.substring(i, i + 2);
                // Convierte el par hexadecimal a un valor numérico
                const encryptedCharCode = parseInt(hexPair, 16);

                if (isNaN(encryptedCharCode)) {
                    return `Error: Carácter inválido encontrado ('${hexPair}' en la posición ${i}).`;
                }

                // Realiza la operación XOR con el carácter correspondiente de la clave Vigenere
                const decryptedCharCode = encryptedCharCode ^ vigenereKey[startIndex % vigenereKey.length];
                // Convierte el código de carácter resultante a un carácter y lo añade al resultado
                decrypted += String.fromCharCode(decryptedCharCode);

                // Incrementa el índice para el siguiente carácter de la clave
                startIndex++;
            }
            return decrypted;
        } catch (e) {
            console.error("Error durante la decodificación:", e);
            return `Error inesperado durante la decodificación. Detalles: ${e.message}`;
        }
    }

    // Event listener para el envío del formulario
    decodeForm.addEventListener('submit', (event) => {
        event.preventDefault(); // Evita que la página se recargue
        const encryptedPassword = type7Input.value.trim();
        const decryptedPassword = decodeType7(encryptedPassword);
        resultOutput.value = decryptedPassword; // Muestra el resultado en el textarea
    });
});
