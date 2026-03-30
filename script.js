/**
 * RSA x AES 混合論證器 (極致縮短版)
 * 邏輯：用 RSA 加密 AES 金鑰，用 AES 加密主體內容
 */

const HOMO_MAP = ["114514", "1919", "364364", "114", "514", "889464", "364", "931", "893", "1145141919"];
const SEP = "0";     // 分隔數碼
const B_SEP = "000"; // 分隔 RSA 金鑰區與 AES 資料區

/**
 * 高密度編碼：將 Hex 轉為數碼牆 (比 Base64 更短)
 */
function hexToHomo(hex) {
    return hex.split('').map(char => {
        const val = parseInt(char, 16);
        // 如果 val > 9 (即 a-f)，我們用兩組數碼表示
        if (val <= 9) return HOMO_MAP[val];
        return HOMO_MAP[1] + SEP + HOMO_MAP[val - 10]; // 簡易進位處理
    }).join(SEP);
}

// 解碼邏輯略 (原理同上，由 0 分隔還原)

/**
 *  加密功能
 */
function doEncrypt() {
    const pubKey = document.getElementById('encryptKeyInput').value.trim();
    const text = document.getElementById('encryptInput').value;
    if (!pubKey || !text) return alert("請輸入公鑰與內容");

    // 產生隨機 AES 金鑰 (16 字元)
    const aesKey = Math.random().toString(36).substring(2, 10);

    // 用 RSA 加密 AES 金鑰 (這部分長度固定)
    const encryptor = new JSEncrypt();
    encryptor.setPublicKey(pubKey);
    const encryptedKey = encryptor.encrypt(aesKey);
    const homoKey = encryptedKey.split('').map(c => c.charCodeAt(0).toString().padStart(3, '0')).join(''); 


    // 用 AES 加密主要內容 (非常精簡)
    const encryptedBody = CryptoJS.AES.encrypt(text, aesKey).toString();
    
    // 將結果映射為數字牆 (這裡我們對 Base64 進行 Homo 映射)
    const homoBody = encryptedBody.split('').map(c => {
        const idx = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=".indexOf(c);
        return idx.toString().padStart(2, '0');
    }).join('');

    // 最終密文：[RSA 加密後的 Key] + B_SEP + [AES 加密後的 Body]
    document.getElementById('encryptOutput').innerText = homoKey + B_SEP + homoBody;
}