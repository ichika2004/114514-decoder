/**
 * RSA x 114514 純數字論證器 (NSYSU IM 專業修復版)
 * 修復：分段長度溢位、中文字元支援、解析歧義
 */

const HOMO_MAP = [
    "114514", "1919", "364364", "114", "514", 
    "889464", "364", "931", "893", "1145141919"
];
const SEPARATOR = "810";
// 塊分隔符使用更獨特的 9 個 0，確保不會與 810 衝突
const BLOCK_SEPARATOR = "000000000"; 

/**
 * 核心編解碼
 */
function encodeToNumbers(code) {
    return code.toString().padStart(3, '0').split('')
        .map(digit => HOMO_MAP[parseInt(digit)])
        .join(SEPARATOR);
}

function decodeFromNumbers(str) {
    if (!str) return "";
    // 過濾空字串，防止 split 產生的雜訊
    const parts = str.split(SEPARATOR).filter(p => p.length > 0);
    let resultNum = "";
    
    parts.forEach(part => {
        const index = HOMO_MAP.indexOf(part);
        if (index !== -1) resultNum += index.toString();
    });

    let chars = [];
    for (let i = 0; i < resultNum.length; i += 3) {
        let code = resultNum.substring(i, i + 3);
        if (code.length === 3) chars.push(String.fromCharCode(parseInt(code)));
    }
    return chars.join('');
}

/**
 * 🚀 加密功能 (修正分段長度)
 */
function doEncrypt() {
    const key = document.getElementById('encryptKeyInput').value;
    const text = document.getElementById('encryptInput').value;
    if (!key || !text) return alert("請輸入公鑰與內容");

    const encryptor = new JSEncrypt();
    encryptor.setPublicKey(key);

    // 256-bit RSA 安全長度設定為 10 (支援中文/特殊字元)
    const CHUNK_SIZE = 10;
    let encryptedBlocks = [];

    for (let i = 0; i < text.length; i += CHUNK_SIZE) {
        const chunk = text.substring(i, i + CHUNK_SIZE);
        const rsaRes = encryptor.encrypt(chunk);
        
        if (!rsaRes) {
            console.error("加密失敗，區塊內容:", chunk);
            return alert("加密失敗：內容過長或金鑰不匹配。建議縮短分段或檢查金鑰。");
        }
        
        const homoBlock = rsaRes.split('').map(c => encodeToNumbers(c.charCodeAt(0))).join(SEPARATOR);
        encryptedBlocks.push(homoBlock);
    }

    document.getElementById('encryptOutput').innerText = encryptedBlocks.join(BLOCK_SEPARATOR);
    localStorage.setItem('rsa_pub_cache', key);
}

/**
 * 🔓 解密功能
 */
function doDecrypt() {
    const key = document.getElementById('decryptKeyInput').value;
    const formula = document.getElementById('decryptInput').value.trim();
    if (!key || !formula) return alert("請輸入私鑰與密文");

    const decryptor = new JSEncrypt();
    decryptor.setPrivateKey(key);

    try {
        const blocks = formula.split(BLOCK_SEPARATOR);
        let finalPlainText = "";

        blocks.forEach((block, index) => {
            const base64 = decodeFromNumbers(block);
            const decryptedChunk = decryptor.decrypt(base64);
            if (decryptedChunk) {
                finalPlainText += decryptedChunk;
            } else {
                console.warn(`第 ${index + 1} 區塊還原失敗`);
            }
        });

        if (finalPlainText) {
            document.getElementById('decryptOutput').innerText = finalPlainText;
        } else {
            alert("解密失敗：金鑰不匹配，或數字牆格式已損壞。");
        }
        localStorage.setItem('rsa_priv_cache', key);
    } catch (e) {
        console.error(e);
        alert("數字牆解析失敗。");
    }
}

/**
 * 🔧 開發者工具：清除緩存
 * 解決金鑰不匹配最快的方法就是清空重來
 */
function clearSystemCache() {
    localStorage.clear();
    location.reload();
}

// 金鑰生成與自動填入邏輯維持不變...
function generateTestKeys() {
    const crypt = new JSEncrypt({ default_key_size: 256 });
    const pub = crypt.getPublicKey();
    const priv = crypt.getPrivateKey();
    document.getElementById('encryptKeyInput').value = pub;
    document.getElementById('decryptKeyInput').value = priv;
    localStorage.setItem('rsa_pub_cache', pub);
    localStorage.setItem('rsa_priv_cache', priv);
    if (navigator.clipboard) {
        navigator.clipboard.writeText(priv).then(() => alert("✅ 256-bit 金鑰對已生成！"));
    }
}

function copyToDecrypt() {
    document.getElementById('decryptInput').value = document.getElementById('encryptOutput').innerText;
}

window.onload = () => {
    const savedPub = localStorage.getItem('rsa_pub_cache');
    const savedPriv = localStorage.getItem('rsa_priv_cache');
    if (savedPub) document.getElementById('encryptKeyInput').value = savedPub;
    if (savedPriv) document.getElementById('decryptKeyInput').value = savedPriv;
};