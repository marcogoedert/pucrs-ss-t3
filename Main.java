/*
 * Author: Marco Antônio Gonçalves Goedert
 * Date: 2023-06-15
 * Assignment Goal: This assignment aims to simulate part of the operation of HTTPS.
 * 
 * Extracted values:
 *  - p: B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371
 *  - g: A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5
 *  - a: 213161804352812231620970763523475575433
 *  - A: 00A836905E78CD78CF5E5425F0F25995D3221DEC7B4B7A267E33D3D1CD1402F26D51C875C4B59F7F6C90626BF9974D49F29E3630C9FA596F799E13A2114D7AF7659C22C48A5142014330B731AD3EF11B1F47E5551A9A450C6EDABBE0B367099A30EA631FD522040DA276B824A78E83F6071C5AB0C285F48F3DC336BACE388E9AA1
 *  - B: 6AB76C5515B79C32F138B8866047FE15834778648E1D893357F6D1F71A5AFE31FD2FF05920F8DCEAB22D1D2858E3C60B256F1EAFCC3ECD0C32C3ADE1F9FE980BB7BE6184F7FD7DFB55DBA243E146B735920AF2D7F8ABAFF97571AA69F2B382E85C37354173AC0292D688EF5437FC722E7F89A2F19A7F216DBFED6FA6C1B2569B
 *  - V: 0B7911BCDC27D518642A89FF58638E185275F5E338D0ED8F5F3D6833F93A4D967838A05FF6AC62897C021128CE2CC394CEE7C01FF005EBD486E3DA542647D201F690FDE3ABB19CBE27B8754A20A3D56850A122872C64B93769DCAEEC380C4413BCBDD9E6C3C5D38F9C296A4AEC719204A2FA7D74B105B5241B50F620995E4DD2
 *  - S: 5FA4599C936A8DFC2A08838D9317EA90
 *  - ciphered msg: 062F549906B15A27EB4CDB9D9539F71CCCF05805F0D9D439C0BEF6689884C4AB6E9716E83094A00B562DD3564196EAFD478D99FE031C891AD7AF0A9A26911D08CD9FECFDF883163BC063510CAA5C46508BC5A55999317855F5F9E5C3402FF116D680A487066D6A1904D831CC6214D6A1
 *  - deciphered msg: "Show Marco. Agora inverte esta mensagem e me envia ela de volta cifrada com a mesma senha"
 *  - reversed deciphered msg: "ahnes amsem a moc adarfic atlov ed ale aivne em e megasnem atse etrevni arogA .ocraM wohS"
 *  - reversed ciphered msg: FF55D9896B14AF68C41F372AB81A020337F0512B906E1DE81E28AB2369EE096C3198E1E0706656AFBB67ECD1230E485D89903154787022710690B87568B5F3529D8A1AF27BB44078FA17D73C5DBA010CB160473A4AE8F205F966FAF7C76DFFEB987FA1650FD18E39719FA85B99740778
 */

import java.math.BigInteger;

public class Main {
    private static BigInteger A, V;
    private static String secret, decipheredMessage, decipheredReversedMessage, cypheredReversedMessage;

    public static void main(String[] args) throws Exception {

        // Step 1
        System.out.println("\nHTTPS SIMULATION START.");

        System.out.println("\n# Step 1: Key Generation Using Diffie-Hellman Algorithm\n");

        System.out.println("## Given the constants below: ");
        System.out.println("- p (prime number): " + Utils.parseBigIntToHexString(Constants.p));
        System.out.println("- g (Z*p generator): " + Utils.parseBigIntToHexString(Constants.g));
        System.out.println("- a (prime number smaller than p with at least 30 digits): " + Constants.a.toString());

        // Substep 1.1
        System.out.println("\n## Calculate key A (A = g^a mod p): ");
        A = Constants.g.modPow(Constants.a, Constants.p);
        System.out.println("- A: " + Utils.parseBigIntToHexString(A));

        // Substep 1.2
        System.out.println("\n## Send key A to professor and receive key B: ");
        System.out.println("- B: " + Utils.parseBigIntToHexString(Constants.B));

        // Substep 1.3
        System.out.println("\n## Calculate V (B^a mod p): ");
        V = Constants.B.modPow(Constants.a, Constants.p);
        System.out.println("- V: " + Utils.parseBigIntToHexString(V));

        // Substep 1.4
        System.out.println("\n## Create secret (S = SHA256(V)): ");
        try {
            secret = Utils.createSecret(V, Constants.SECRET_LENGTH);
            System.out.println("- Secret: " + secret);
        } catch (Exception e) {
            System.out.println("- Error while creating secret: " + e.getMessage());
            return;
        }

        // Step 2
        System.out.println("\n# Step 2: Message Exchange\n");

        System.out.println(
                "## Given the hex message ciphered with AES (with CBC operation and padding) received from the professor:");
        System.out.println("- Professor ciphered message: " + Constants.CYPHERED_MESSAGE);

        // Substep 2.1
        System.out.println("\n## Decipher the message: ");
        decipheredMessage = AES.decipher(secret, Constants.CYPHERED_MESSAGE);
        System.out.println("- Deciphered message: " + decipheredMessage);

        // Substep 2.2
        System.out.println("\n## Reverse the message: ");
        decipheredReversedMessage = Utils.reverseString(decipheredMessage);
        System.out.println("- Reversed deciphered message: " + decipheredReversedMessage);

        // Substep 2.3
        System.out.println("\n## Cipher the reversed message and send it to the professor: ");
        cypheredReversedMessage = AES.cipher(secret, decipheredReversedMessage);
        System.out.println("- Reversed ciphered message: " + cypheredReversedMessage);

        // Test
        System.out.println("\n# Final result (uncrypted message the professor will receive):");
        String result = AES.decipher(secret, cypheredReversedMessage);
        System.out.println("- Message: " + result);

        System.out.println("\nHTTPS SIMULATION FINISH.\n");
    }

}