// 상태 관리
let currentSecretId = null;
let passwordCallback = null;
let currentUserRole = null; // 'read' 또는 'admin'
let adminModeSecretId = null; // 관리자 모드에서 선택된 비밀글 ID

// 관리자 모드 비밀번호 관리
function getAdminPassword() {
    const password = localStorage.getItem('adminModePassword');
    return password || '1102'; // 기본 비밀번호
}

function setAdminPassword(password) {
    localStorage.setItem('adminModePassword', password);
}

function verifyAdminPassword(password) {
    return password === getAdminPassword();
}

// 화면 전환
function showScreen(screenId) {
    document.querySelectorAll('.screen').forEach(screen => {
        screen.classList.remove('active');
    });
    document.getElementById(screenId).classList.add('active');
}

// LocalStorage 관리
function getSecrets() {
    const data = localStorage.getItem('secrets');
    return data ? JSON.parse(data) : [];
}

function saveSecrets(secrets) {
    localStorage.setItem('secrets', JSON.stringify(secrets));
}

// 비밀번호 해시 생성 (검증용)
async function hashPassword(password) {
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    const hash = await crypto.subtle.digest('SHA-256', data);
    return arrayBufferToBase64(hash);
}

// 비밀번호 검증
async function verifyPassword(password, passwordHash) {
    const hash = await hashPassword(password);
    return hash === passwordHash;
}

// 비밀글 권한 확인 (읽기용 또는 관리자용)
async function checkSecretPermission(secret, password) {
    // 이전 버전 호환성: 비밀번호 해시가 없으면 복호화 시도로 확인
    if (!secret.adminPasswordHash && !secret.readPasswordHash) {
        // 이전 버전 글: 비밀번호로 복호화 시도
        try {
            await decryptWithPassword({
                ciphertext: secret.ciphertext,
                salt: secret.encryptedKey,
                iv: secret.iv
            }, password);
            // 복호화 성공 시 관리자 권한으로 간주 (이전 버전은 관리자만 있었음)
            return 'admin';
        } catch (error) {
            return null;
        }
    }
    
    // 관리자 비밀번호 먼저 확인
    if (secret.adminPasswordHash) {
        const isAdmin = await verifyPassword(password, secret.adminPasswordHash);
        if (isAdmin) {
            return 'admin';
        }
    }
    
    // 읽기용 비밀번호 확인
    if (secret.readPasswordHash) {
        const isRead = await verifyPassword(password, secret.readPasswordHash);
        if (isRead) {
            return 'read';
        }
    }
    
    return null; // 비밀번호가 맞지 않음
}

// 참고: WebCrypto API의 제한으로 인해 PRD의 RSA-OAEP 요구사항 대신
// 비밀번호 기반 PBKDF2 + AES-GCM 방식을 사용합니다.
// 이는 동일한 비밀번호로 동일한 키를 생성할 수 있는 더 실용적인 방법입니다.

// 암호화 함수 (단일 비밀번호로 암호화)
async function encryptWithPassword(content, password) {
    // 각 비밀글마다 고유한 salt 생성
    const salt = crypto.getRandomValues(new Uint8Array(16));
    
    // 비밀번호로부터 마스터 키 생성
    const encoder = new TextEncoder();
    const passwordKey = await crypto.subtle.importKey(
        'raw',
        encoder.encode(password),
        'PBKDF2',
        false,
        ['deriveKey']
    );
    
    const masterKey = await crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt: salt,
            iterations: 100000,
            hash: 'SHA-256'
        },
        passwordKey,
        {
            name: 'AES-GCM',
            length: 256
        },
        false,
        ['encrypt', 'decrypt']
    );
    
    // IV 생성
    const iv = crypto.getRandomValues(new Uint8Array(12));
    
    // 내용을 AES로 암호화
    const encryptedContent = await crypto.subtle.encrypt(
        {
            name: 'AES-GCM',
            iv: iv
        },
        masterKey,
        encoder.encode(content)
    );
    
    // Base64 인코딩
    const ciphertext = arrayBufferToBase64(encryptedContent);
    const saltB64 = arrayBufferToBase64(salt);
    const ivB64 = arrayBufferToBase64(iv);
    
    return {
        ciphertext,
        salt: saltB64,
        iv: ivB64
    };
}

// 복호화 함수 (비밀번호로 복호화)
async function decryptWithPassword(secretData, password) {
    try {
        // 저장된 salt 가져오기
        const salt = base64ToArrayBuffer(secretData.salt);
        
        // 비밀번호로부터 마스터 키 생성
        const encoder = new TextEncoder();
        const passwordKey = await crypto.subtle.importKey(
            'raw',
            encoder.encode(password),
            'PBKDF2',
            false,
            ['deriveKey']
        );
        
        const masterKey = await crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: 100000,
                hash: 'SHA-256'
            },
            passwordKey,
            {
                name: 'AES-GCM',
                length: 256
            },
            false,
            ['decrypt']
        );
        
        // 내용 복호화
        const ciphertext = base64ToArrayBuffer(secretData.ciphertext);
        const iv = base64ToArrayBuffer(secretData.iv);
        
        const decryptedContent = await crypto.subtle.decrypt(
            {
                name: 'AES-GCM',
                iv: iv
            },
            masterKey,
            ciphertext
        );
        
        const decoder = new TextDecoder();
        return decoder.decode(decryptedContent);
    } catch (error) {
        throw new Error('복호화 실패: 비밀번호가 올바르지 않습니다.');
    }
}

// 복호화 함수 (관리자 비밀번호로 복호화) - 호환성
async function decryptSecret(secret, adminPassword) {
    updateProgress('키 생성 중...', 20);
    updateProgress('내용 복호화 중...', 60);
    const content = await decryptWithPassword({
        ciphertext: secret.adminCiphertext || secret.ciphertext,
        salt: secret.adminSalt || secret.encryptedKey,
        iv: secret.adminIv || secret.iv
    }, adminPassword);
    updateProgress('완료', 100);
    return content;
}

// Base64 변환 유틸리티
function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

function base64ToArrayBuffer(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
}

// 진행 상태 업데이트
function updateProgress(message, percent, type = 'encrypt') {
    const progressFill = document.getElementById(type === 'encrypt' ? 'encryptProgressFill' : 'editProgressFill');
    const statusText = document.getElementById(type === 'encrypt' ? 'encryptStatus' : 'editStatus');
    const progressContainer = document.getElementById(type === 'encrypt' ? 'encryptProgress' : 'editProgress');
    
    if (progressFill) progressFill.style.width = percent + '%';
    if (statusText) statusText.textContent = message;
    if (progressContainer) progressContainer.classList.remove('hidden');
    
    if (percent === 100) {
        setTimeout(() => {
            if (progressContainer) progressContainer.classList.add('hidden');
        }, 1000);
    }
}

// 비밀글 목록 렌더링
function renderSecretList() {
    const secrets = getSecrets();
    const listContainer = document.getElementById('secretList');
    
    if (secrets.length === 0) {
        listContainer.innerHTML = '<p style="text-align: center; color: #888;">저장된 비밀글이 없습니다.</p>';
        return;
    }
    
    listContainer.innerHTML = secrets.map(secret => {
        const date = new Date(secret.createdAt);
        const dateStr = date.toLocaleDateString('ko-KR', {
            year: 'numeric',
            month: 'long',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        });
        
        return `
            <div class="secret-item">
                <div class="secret-item-title">${escapeHtml(secret.title)}</div>
                <div class="secret-item-date">${dateStr}</div>
                <div class="secret-item-actions">
                    <button class="btn-small btn-read" data-id="${secret.id}">읽기</button>
                    <button class="btn-small btn-edit" data-id="${secret.id}">수정</button>
                    <button class="btn-small btn-delete" data-id="${secret.id}">삭제</button>
                </div>
            </div>
        `;
    }).join('');
    
    // 이벤트 리스너 추가
    listContainer.querySelectorAll('.btn-read').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const id = e.target.getAttribute('data-id');
            showPasswordModal('비밀글 읽기', (password) => {
                readSecret(id, password);
            });
        });
    });
    
    listContainer.querySelectorAll('.btn-edit').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const id = e.target.getAttribute('data-id');
            showPasswordModal('비밀글 수정', (password) => {
                editSecret(id, password);
            });
        });
    });
    
    listContainer.querySelectorAll('.btn-delete').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const id = e.target.getAttribute('data-id');
            showPasswordModal('비밀글 삭제', (password) => {
                deleteSecret(id, password);
            });
        });
    });
}

// 비밀글 읽기
async function readSecret(id, password) {
    try {
        const secrets = getSecrets();
        const secret = secrets.find(s => s.id === id);
        
        if (!secret) {
            alert('비밀글을 찾을 수 없습니다.');
            return;
        }
        
        // 권한 확인
        const role = await checkSecretPermission(secret, password);
        if (!role) {
            alert('비밀번호가 올바르지 않습니다.');
            document.getElementById('passwordModal').classList.add('hidden');
            return;
        }
        
        // 진행바 표시
        const decryptProgress = document.getElementById('decryptProgress');
        const decryptProgressFill = document.getElementById('decryptProgressFill');
        const decryptStatus = document.getElementById('decryptStatus');
        
        if (decryptProgress) {
            decryptProgress.classList.remove('hidden');
            if (decryptProgressFill) decryptProgressFill.style.width = '50%';
            if (decryptStatus) decryptStatus.textContent = '복호화 중...';
        }
        
        // 권한에 따라 적절한 암호화 버전 복호화
        let content;
        try {
            if (role === 'admin') {
                content = await decryptWithPassword({
                    ciphertext: secret.adminCiphertext || secret.ciphertext,
                    salt: secret.adminSalt || secret.encryptedKey,
                    iv: secret.adminIv || secret.iv
                }, password);
            } else {
                // 읽기 전용 비밀번호 사용
                // 이전 버전 호환성: readCiphertext가 없으면 adminCiphertext 사용 시도
                if (secret.readCiphertext && secret.readSalt && secret.readIv) {
                    content = await decryptWithPassword({
                        ciphertext: secret.readCiphertext,
                        salt: secret.readSalt,
                        iv: secret.readIv
                    }, password);
                } else {
                    // 이전 버전 글인 경우 관리자 암호화 버전 사용 시도 (호환성)
                    content = await decryptWithPassword({
                        ciphertext: secret.ciphertext,
                        salt: secret.encryptedKey,
                        iv: secret.iv
                    }, password);
                }
            }
        } catch (decryptError) {
            throw new Error('복호화 실패: 비밀번호가 올바르지 않거나 데이터가 손상되었습니다.');
        }
        
        // 진행바 숨기기
        if (decryptProgress) {
            if (decryptProgressFill) decryptProgressFill.style.width = '100%';
            if (decryptStatus) decryptStatus.textContent = '완료';
            setTimeout(() => {
                decryptProgress.classList.add('hidden');
            }, 500);
        }
        
        document.getElementById('decryptContent').textContent = `제목: ${secret.title}\n\n${content}`;
        showScreen('decryptScreen');
        document.getElementById('passwordModal').classList.add('hidden');
        
        // 현재 사용자 역할 저장
        currentUserRole = role;
        currentSecretId = id;
    } catch (error) {
        alert(error.message);
        const decryptProgress = document.getElementById('decryptProgress');
        if (decryptProgress) decryptProgress.classList.add('hidden');
        document.getElementById('passwordModal').classList.add('hidden');
    }
}

// 비밀글 수정
async function editSecret(id, password) {
    try {
        const secrets = getSecrets();
        const secret = secrets.find(s => s.id === id);
        
        if (!secret) {
            alert('비밀글을 찾을 수 없습니다.');
            return;
        }
        
        // 권한 확인 (관리자만 수정 가능)
        const role = await checkSecretPermission(secret, password);
        if (!role || role !== 'admin') {
            alert('수정 권한이 없습니다. 관리자 비밀번호를 입력해주세요.');
            document.getElementById('passwordModal').classList.add('hidden');
            return;
        }
        
        document.getElementById('passwordModal').classList.add('hidden');
        
        // 복호화
        updateProgress('복호화 중...', 50, 'edit');
        const content = await decryptWithPassword({
            ciphertext: secret.adminCiphertext || secret.ciphertext,
            salt: secret.adminSalt || secret.encryptedKey,
            iv: secret.adminIv || secret.iv
        }, password);
        
        // 편집 화면에 내용 표시
        document.getElementById('editTitle').value = secret.title;
        document.getElementById('editContent').value = content;
        document.getElementById('editReadPassword').value = '';
        document.getElementById('editAdminPassword').value = '';
        
        currentSecretId = id;
        currentUserRole = 'admin';
        showScreen('editScreen');
        document.getElementById('editProgress').classList.add('hidden');
    } catch (error) {
        alert(error.message);
    }
}

// 비밀글 수정 저장
async function saveEdit() {
    try {
        const title = document.getElementById('editTitle').value.trim();
        const content = document.getElementById('editContent').value.trim();
        const newReadPassword = document.getElementById('editReadPassword')?.value || '';
        const newAdminPassword = document.getElementById('editAdminPassword')?.value || '';
        
        if (!title || !content) {
            alert('제목과 내용을 모두 입력해주세요.');
            return;
        }
        
        if (!currentSecretId) {
            alert('수정할 비밀글 정보를 찾을 수 없습니다.');
            return;
        }
        const secrets = getSecrets();
        const secret = secrets.find(s => s.id === currentSecretId);
        
        if (!secret) {
            alert('비밀글을 찾을 수 없습니다.');
            return;
        }
        
        // 새 비밀번호 필수 입력
        if (!newReadPassword || !newAdminPassword) {
            alert('수정 시 읽기 전용 비밀번호와 관리자 비밀번호를 모두 입력해야 합니다.');
            return;
        }
        
        updateProgress('암호화 중...', 30, 'edit');
        // 새 비밀번호로 재암호화
        const readEncrypted = await encryptWithPassword(content, newReadPassword);
        updateProgress('관리자 암호화 중...', 60, 'edit');
        const adminEncrypted = await encryptWithPassword(content, newAdminPassword);
        
        updateProgress('비밀번호 해시 생성 중...', 80, 'edit');
        // 새 비밀번호 해시 생성
        const readPasswordHash = await hashPassword(newReadPassword);
        const adminPasswordHash = await hashPassword(newAdminPassword);
        
        updateProgress('저장 중...', 100, 'edit');
        
        // 기존 비밀글 업데이트
        const index = secrets.findIndex(s => s.id === currentSecretId);
        
        secrets[index] = {
            ...secrets[index],
            title: title,
            // 읽기용 암호화
            readCiphertext: readEncrypted.ciphertext,
            readSalt: readEncrypted.salt,
            readIv: readEncrypted.iv,
            // 관리자용 암호화
            adminCiphertext: adminEncrypted.ciphertext,
            adminSalt: adminEncrypted.salt,
            adminIv: adminEncrypted.iv,
            // 호환성을 위한 필드
            ciphertext: adminEncrypted.ciphertext,
            encryptedKey: adminEncrypted.salt,
            iv: adminEncrypted.iv,
            // 비밀번호 해시
            readPasswordHash: readPasswordHash,
            adminPasswordHash: adminPasswordHash,
            updatedAt: new Date().toISOString()
        };
        
        saveSecrets(secrets);
        
        // 목록 화면으로 돌아가기
        renderSecretList();
        showScreen('listScreen');
        currentSecretId = null;
        currentUserRole = null;
        
        // 입력 필드 초기화
        document.getElementById('editTitle').value = '';
        document.getElementById('editContent').value = '';
        document.getElementById('editReadPassword').value = '';
        document.getElementById('editAdminPassword').value = '';
        
    } catch (error) {
        alert('저장 중 오류가 발생했습니다: ' + error.message);
    }
}

// 비밀글 삭제
async function deleteSecret(id, password) {
    try {
        const secrets = getSecrets();
        const secret = secrets.find(s => s.id === id);
        
        if (!secret) {
            alert('비밀글을 찾을 수 없습니다.');
            return;
        }
        
        // 권한 확인 (관리자만 삭제 가능)
        const role = await checkSecretPermission(secret, password);
        if (!role || role !== 'admin') {
            alert('삭제 권한이 없습니다. 관리자 비밀번호를 입력해주세요.');
            document.getElementById('passwordModal').classList.add('hidden');
            return;
        }
        
        // 비밀번호가 맞으면 삭제 확인
        if (confirm('정말 삭제하시겠습니까? 삭제된 내용은 복구할 수 없습니다.')) {
            const filtered = secrets.filter(s => s.id !== id);
            saveSecrets(filtered);
            renderSecretList();
        }
        
        document.getElementById('passwordModal').classList.add('hidden');
    } catch (error) {
        alert('비밀번호가 올바르지 않습니다. 삭제할 수 없습니다.');
    }
}

// 비밀글 저장
async function saveSecret() {
    try {
        const title = document.getElementById('writeTitle').value.trim();
        const content = document.getElementById('writeContent').value.trim();
        const readPassword = document.getElementById('writeReadPassword').value;
        const adminPassword = document.getElementById('writeAdminPassword').value;
        
        if (!title || !content) {
            alert('제목과 내용을 모두 입력해주세요.');
            return;
        }
        
        if (!readPassword || !adminPassword) {
            alert('읽기 전용 비밀번호와 관리자 비밀번호를 모두 입력해주세요.');
            return;
        }
        
        updateProgress('암호화 중...', 20);
        
        // 읽기용 비밀번호로 암호화
        const readEncrypted = await encryptWithPassword(content, readPassword);
        
        updateProgress('관리자 암호화 중...', 60);
        // 관리자 비밀번호로 암호화
        const adminEncrypted = await encryptWithPassword(content, adminPassword);
        
        updateProgress('비밀번호 해시 생성 중...', 80);
        // 비밀번호 해시 생성
        const readPasswordHash = await hashPassword(readPassword);
        const adminPasswordHash = await hashPassword(adminPassword);
        
        updateProgress('저장 중...', 100);
        
        const secrets = getSecrets();
        const newSecret = {
            id: 'msg_' + Date.now(),
            title: title,
            // 읽기용 암호화
            readCiphertext: readEncrypted.ciphertext,
            readSalt: readEncrypted.salt,
            readIv: readEncrypted.iv,
            // 관리자용 암호화
            adminCiphertext: adminEncrypted.ciphertext,
            adminSalt: adminEncrypted.salt,
            adminIv: adminEncrypted.iv,
            // 호환성을 위한 필드
            ciphertext: adminEncrypted.ciphertext,
            encryptedKey: adminEncrypted.salt,
            iv: adminEncrypted.iv,
            // 비밀번호 해시
            readPasswordHash: readPasswordHash,
            adminPasswordHash: adminPasswordHash,
            createdAt: new Date().toISOString()
        };
        
        secrets.push(newSecret);
        saveSecrets(secrets);
        
        // 입력 필드 초기화
        document.getElementById('writeTitle').value = '';
        document.getElementById('writeContent').value = '';
        document.getElementById('writeReadPassword').value = '';
        document.getElementById('writeAdminPassword').value = '';
        
        // 홈 화면으로 이동
        showScreen('homeScreen');
    } catch (error) {
        alert('저장 중 오류가 발생했습니다: ' + error.message);
    }
}

// 비밀번호 입력 모달
function showPasswordModal(title, callback) {
    document.getElementById('passwordModalTitle').textContent = title;
    document.getElementById('modalPassword').value = '';
    document.getElementById('passwordModal').classList.remove('hidden');
    passwordCallback = callback;
}

// HTML 이스케이프
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// 운영자 권한 모드 표시 (비밀번호 확인)
function showAdminMode() {
    showPasswordModal('운영자 권한 모드 비밀번호 입력', (password) => {
        if (verifyAdminPassword(password)) {
            document.getElementById('passwordModal').classList.add('hidden');
            renderAdminSecretList();
            showScreen('adminScreen');
        } else {
            alert('비밀번호가 올바르지 않습니다.');
        }
    });
}

// 관리자 모드 비밀글 목록 렌더링
function renderAdminSecretList() {
    const secrets = getSecrets();
    const listContainer = document.getElementById('adminSecretList');
    
    if (secrets.length === 0) {
        listContainer.innerHTML = '<p style="text-align: center; color: #888;">저장된 비밀글이 없습니다.</p>';
        return;
    }
    
    listContainer.innerHTML = secrets.map(secret => {
        const date = new Date(secret.createdAt);
        const dateStr = date.toLocaleDateString('ko-KR', {
            year: 'numeric',
            month: 'long',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        });
        
        return `
            <div class="secret-item">
                <div class="secret-item-title">${escapeHtml(secret.title)}</div>
                <div class="secret-item-date">${dateStr}</div>
                <div class="secret-item-actions">
                    <button class="btn-small btn-read-admin" data-id="${secret.id}">읽기</button>
                    <button class="btn-small btn-edit-admin" data-id="${secret.id}">수정</button>
                    <button class="btn-small btn-change-password" data-id="${secret.id}">비밀번호 변경</button>
                    <button class="btn-small btn-delete-admin" data-id="${secret.id}">삭제</button>
                </div>
            </div>
        `;
    }).join('');
    
    // 이벤트 리스너 추가
    // 이벤트 위임으로 처리
    listContainer.addEventListener('click', (e) => {
        const id = e.target.getAttribute('data-id');
        if (!id) return;
        
        try {
            if (e.target.classList.contains('btn-read-admin')) {
                readSecretAsAdmin(id);
            } else if (e.target.classList.contains('btn-edit-admin')) {
                editSecretAsAdmin(id);
            } else if (e.target.classList.contains('btn-change-password')) {
                showPasswordChangeModal(id);
            } else if (e.target.classList.contains('btn-delete-admin')) {
                const secret = secrets.find(s => s.id === id);
                if (secret && confirm(`정말 "${secret.title}" 글을 삭제하시겠습니까?\n삭제된 내용은 복구할 수 없습니다.`)) {
                    deleteSecretAsAdmin(id);
                }
            }
        } catch (error) {
            alert('오류 발생: ' + error.message);
        }
    });
}

// 운영자 권한 모드에서 비밀글 읽기 (비밀번호 없이 - 암호문 정보 표시)
async function readSecretAsAdmin(id) {
    try {
        const secrets = getSecrets();
        const secret = secrets.find(s => s.id === id);
        
        if (!secret) {
            alert('비밀글을 찾을 수 없습니다.');
            return;
        }
        
        // 운영자 모드: 암호화된 데이터 정보를 직접 표시
        let content = `제목: ${secret.title}\n\n`;
        content += `[운영자 모드 - 암호화된 데이터 정보]\n\n`;
        content += `작성일: ${secret.createdAt ? new Date(secret.createdAt).toLocaleString('ko-KR') : '알 수 없음'}\n`;
        if (secret.updatedAt) {
            content += `수정일: ${new Date(secret.updatedAt).toLocaleString('ko-KR')}\n`;
        }
        content += `\n암호화 방식: AES-GCM 256bit\n`;
        content += `\n[암호문 데이터]\n`;
        
        if (secret.adminCiphertext) {
            content += `관리자 버전 암호문 길이: ${secret.adminCiphertext.length} 자\n`;
        }
        if (secret.readCiphertext) {
            content += `읽기 전용 버전 암호문 길이: ${secret.readCiphertext.length} 자\n`;
        }
        if (secret.ciphertext && !secret.adminCiphertext) {
            content += `암호문 길이: ${secret.ciphertext.length} 자\n`;
        }
        
        content += `\n[참고]\n`;
        content += `운영자 모드에서는 암호화된 데이터에 직접 접근할 수 있습니다.\n`;
        content += `복호화된 내용을 보려면 해당 비밀글의 비밀번호가 필요합니다.\n`;
        content += `일반 모드에서 해당 비밀번호로 읽기/수정 기능을 사용하세요.`;
        
        document.getElementById('decryptContent').textContent = content;
        showScreen('decryptScreen');
        
    } catch (error) {
        alert('오류 발생: ' + error.message);
    }
}

// 운영자 권한 모드에서 비밀글 수정 (비밀번호 없이 - 새 내용으로 덮어쓰기)
async function editSecretAsAdmin(id) {
    try {
        const secrets = getSecrets();
        const secret = secrets.find(s => s.id === id);
        
        if (!secret) {
            alert('비밀글을 찾을 수 없습니다.');
            return;
        }
        
        // 운영자 모드: 비밀번호 없이 새 내용으로 수정 가능
        // 편집 화면에 제목만 표시하고 내용은 빈 상태
        document.getElementById('editTitle').value = secret.title;
        document.getElementById('editContent').value = '';
        document.getElementById('editReadPassword').value = '';
        document.getElementById('editAdminPassword').value = '';
        
        currentSecretId = id;
        showScreen('editScreen');
        
    } catch (error) {
        alert('오류 발생: ' + error.message);
    }
}

// 운영자 권한 모드에서 비밀글 삭제 (비밀번호 없이)
function deleteSecretAsAdmin(id) {
    try {
        const secrets = getSecrets();
        const secret = secrets.find(s => s.id === id);
        
        if (!secret) {
            alert('비밀글을 찾을 수 없습니다.');
            return;
        }
        
        const filtered = secrets.filter(s => s.id !== id);
        saveSecrets(filtered);
        renderAdminSecretList();
    } catch (error) {
        alert('삭제 중 오류 발생: ' + error.message);
    }
}

// 비밀번호 변경 모달 표시
function showPasswordChangeModal(id) {
    try {
        adminModeSecretId = id;
        document.getElementById('changeReadPassword').value = '';
        document.getElementById('changeAdminPassword').value = '';
        document.getElementById('passwordChangeModal').classList.remove('hidden');
    } catch (error) {
        alert('모달 열기 오류: ' + error.message);
    }
}

// 관리자 비밀번호 변경 모달 표시
function showAdminPasswordChangeModal() {
    document.getElementById('currentAdminPassword').value = '';
    document.getElementById('newAdminPassword').value = '';
    document.getElementById('confirmNewAdminPassword').value = '';
    document.getElementById('adminPasswordChangeModal').classList.remove('hidden');
}

// 운영자 비밀번호 변경
function changeAdminPassword() {
    try {
        const currentPassword = document.getElementById('currentAdminPassword').value;
        const newPassword = document.getElementById('newAdminPassword').value;
        const confirmPassword = document.getElementById('confirmNewAdminPassword').value;
        
        if (!currentPassword || !newPassword || !confirmPassword) {
            alert('모든 필드를 입력해주세요.');
            return;
        }
        
        if (!verifyAdminPassword(currentPassword)) {
            alert('현재 비밀번호가 올바르지 않습니다.');
            return;
        }
        
        if (newPassword !== confirmPassword) {
            alert('새 비밀번호와 확인 비밀번호가 일치하지 않습니다.');
            return;
        }
        
        if (newPassword.length < 4) {
            alert('비밀번호는 최소 4자 이상이어야 합니다.');
            return;
        }
        
        setAdminPassword(newPassword);
        document.getElementById('adminPasswordChangeModal').classList.add('hidden');
        
        // 입력 필드 초기화
        document.getElementById('currentAdminPassword').value = '';
        document.getElementById('newAdminPassword').value = '';
        document.getElementById('confirmNewAdminPassword').value = '';
    } catch (error) {
        alert('비밀번호 변경 중 오류 발생: ' + error.message);
    }
}

// 비밀번호 변경 (비밀글 비밀번호)
async function changePassword() {
    try {
        const readPassword = document.getElementById('changeReadPassword').value;
        const adminPassword = document.getElementById('changeAdminPassword').value;
        
        if (!readPassword || !adminPassword) {
            alert('읽기 전용 비밀번호와 관리자 비밀번호를 모두 입력해주세요.');
            return;
        }
        
        if (!adminModeSecretId) {
            alert('비밀글 정보를 찾을 수 없습니다.');
            return;
        }
        
        const secrets = getSecrets();
        const secret = secrets.find(s => s.id === adminModeSecretId);
        
        if (!secret) {
            alert('비밀글을 찾을 수 없습니다.');
            return;
        }
        
        // 운영자 모드에서는 기존 내용 복호화 없이 새 비밀번호로만 저장
        // 임시 내용으로 새 비밀번호 설정 (기존 내용 복호화 불가능)
        const tempContent = '';
        
        // 새 비밀번호로 재암호화
        const readEncrypted = await encryptWithPassword(tempContent, readPassword);
        const adminEncrypted = await encryptWithPassword(tempContent, adminPassword);
        
        // 비밀번호 해시 생성
        const readPasswordHash = await hashPassword(readPassword);
        const adminPasswordHash = await hashPassword(adminPassword);
        
        // 업데이트
        const index = secrets.findIndex(s => s.id === adminModeSecretId);
        if (index === -1) {
            alert('비밀글을 찾을 수 없습니다.');
            return;
        }
        
        secrets[index] = {
            ...secrets[index],
            // 읽기용 암호화
            readCiphertext: readEncrypted.ciphertext,
            readSalt: readEncrypted.salt,
            readIv: readEncrypted.iv,
            // 관리자용 암호화
            adminCiphertext: adminEncrypted.ciphertext,
            adminSalt: adminEncrypted.salt,
            adminIv: adminEncrypted.iv,
            // 호환성
            ciphertext: adminEncrypted.ciphertext,
            encryptedKey: adminEncrypted.salt,
            iv: adminEncrypted.iv,
            // 비밀번호 해시
            readPasswordHash: readPasswordHash,
            adminPasswordHash: adminPasswordHash,
            updatedAt: new Date().toISOString()
        };
        
        saveSecrets(secrets);
        
        // 모달 닫기
        document.getElementById('passwordChangeModal').classList.add('hidden');
        document.getElementById('passwordModal')?.classList.add('hidden');
        
        // 입력 필드 초기화
        document.getElementById('changeReadPassword').value = '';
        document.getElementById('changeAdminPassword').value = '';
        
        renderAdminSecretList();
        adminModeSecretId = null;
        
    } catch (error) {
        alert('비밀번호 변경 중 오류 발생: ' + error.message);
    }
}

// 이벤트 리스너 설정
document.addEventListener('DOMContentLoaded', () => {
    // 홈 화면 버튼
    document.getElementById('btnWrite')?.addEventListener('click', () => {
        try {
            showScreen('writeScreen');
        } catch (error) {
            alert('화면 전환 오류: ' + error.message);
        }
    });
    
    document.getElementById('btnRead')?.addEventListener('click', () => {
        try {
            renderSecretList();
            showScreen('listScreen');
        } catch (error) {
            alert('목록 표시 오류: ' + error.message);
        }
    });
    
    // 작성 화면 버튼
    document.getElementById('btnSave')?.addEventListener('click', () => {
        try {
            saveSecret();
        } catch (error) {
            alert('저장 오류: ' + error.message);
        }
    });
    
    document.getElementById('btnCancelWrite')?.addEventListener('click', () => {
        try {
            showScreen('homeScreen');
        } catch (error) {
            alert('화면 전환 오류: ' + error.message);
        }
    });
    
    // 수정 화면 버튼
    document.getElementById('btnSaveEdit')?.addEventListener('click', () => {
        try {
            saveEdit();
        } catch (error) {
            alert('수정 저장 오류: ' + error.message);
        }
    });
    
    document.getElementById('btnCancelEdit')?.addEventListener('click', () => {
        try {
            renderSecretList();
            showScreen('listScreen');
            currentSecretId = null;
            currentUserRole = null;
        } catch (error) {
            alert('화면 전환 오류: ' + error.message);
        }
    });
    
    // 복호화 화면 버튼
    document.getElementById('btnCloseDecrypt')?.addEventListener('click', () => {
        try {
            renderSecretList();
            showScreen('listScreen');
            currentSecretId = null;
            currentUserRole = null;
        } catch (error) {
            alert('화면 전환 오류: ' + error.message);
        }
    });
    
    // 목록 화면 버튼
    document.getElementById('btnBackToList')?.addEventListener('click', () => {
        try {
            showScreen('homeScreen');
        } catch (error) {
            alert('화면 전환 오류: ' + error.message);
        }
    });
    
    // 비밀번호 모달 버튼
    document.getElementById('btnConfirmPassword')?.addEventListener('click', () => {
        try {
            const password = document.getElementById('modalPassword').value;
            if (!password) {
                alert('비밀번호를 입력해주세요.');
                return;
            }
            if (passwordCallback) {
                passwordCallback(password);
            } else {
                alert('비밀번호 처리 함수가 설정되지 않았습니다.');
            }
        } catch (error) {
            alert('비밀번호 확인 오류: ' + error.message);
        }
    });
    
    document.getElementById('btnCancelPassword')?.addEventListener('click', () => {
        try {
            document.getElementById('passwordModal').classList.add('hidden');
            passwordCallback = null;
        } catch (error) {
            alert('모달 닫기 오류: ' + error.message);
        }
    });
    
    // Enter 키로 비밀번호 확인
    document.getElementById('modalPassword')?.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            try {
                document.getElementById('btnConfirmPassword')?.click();
            } catch (error) {
                alert('비밀번호 확인 오류: ' + error.message);
            }
        }
    });
    
    // 수정 화면에서 Enter 키로 저장
    document.getElementById('editReadPassword')?.addEventListener('keypress', (e) => {
        if (e.key === 'Enter' && e.ctrlKey) {
            try {
                document.getElementById('btnSaveEdit')?.click();
            } catch (error) {
                alert('저장 오류: ' + error.message);
            }
        }
    });
    
    document.getElementById('editAdminPassword')?.addEventListener('keypress', (e) => {
        if (e.key === 'Enter' && e.ctrlKey) {
            try {
                document.getElementById('btnSaveEdit')?.click();
            } catch (error) {
                alert('저장 오류: ' + error.message);
            }
        }
    });
    
    // 운영자 모드 버튼들은 이벤트 위임으로 처리 (중복 클릭 방지)
    let lastClickTime = {};
    document.addEventListener('click', (e) => {
        const now = Date.now();
        const buttonId = e.target.id;
        
        // 중복 클릭 방지 (500ms 이내 중복 클릭 무시)
        if (lastClickTime[buttonId] && now - lastClickTime[buttonId] < 500) {
            return;
        }
        lastClickTime[buttonId] = now;
        
        if (buttonId === 'btnExitAdmin') {
            try {
                showScreen('homeScreen');
                adminModeSecretId = null;
                document.getElementById('passwordModal')?.classList.add('hidden');
            } catch (error) {
                alert('오류 발생: ' + error.message);
            }
        } else if (buttonId === 'btnChangeAdminPassword') {
            try {
                showAdminPasswordChangeModal();
            } catch (error) {
                alert('오류 발생: ' + error.message);
            }
        } else if (buttonId === 'btnRefreshAdmin') {
            try {
                renderAdminSecretList();
            } catch (error) {
                alert('오류 발생: ' + error.message);
            }
        }
    });
    
    // 비밀번호 변경 모달 버튼 (중복 클릭 방지 포함)
    let passwordChangeClickTime = 0;
    document.getElementById('btnConfirmPasswordChange')?.addEventListener('click', async () => {
        const now = Date.now();
        if (now - passwordChangeClickTime < 500) return;
        passwordChangeClickTime = now;
        
        try {
            await changePassword();
        } catch (error) {
            alert('비밀번호 변경 중 오류 발생: ' + error.message);
        }
    });
    
    let cancelPasswordChangeClickTime = 0;
    document.getElementById('btnCancelPasswordChange')?.addEventListener('click', () => {
        const now = Date.now();
        if (now - cancelPasswordChangeClickTime < 500) return;
        cancelPasswordChangeClickTime = now;
        
        try {
            document.getElementById('passwordChangeModal').classList.add('hidden');
            adminModeSecretId = null;
        } catch (error) {
            alert('모달 닫기 중 오류 발생: ' + error.message);
        }
    });
    
    // 비밀번호 변경 모달에서 Enter 키
    document.getElementById('changeAdminPassword').addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            document.getElementById('btnConfirmPasswordChange').click();
        }
    });
    
    // 운영자 비밀번호 변경 모달 버튼 (중복 클릭 방지 포함)
    let adminPasswordChangeClickTime = 0;
    document.getElementById('btnConfirmAdminPasswordChange')?.addEventListener('click', () => {
        const now = Date.now();
        if (now - adminPasswordChangeClickTime < 500) return;
        adminPasswordChangeClickTime = now;
        
        try {
            changeAdminPassword();
        } catch (error) {
            alert('운영자 비밀번호 변경 중 오류 발생: ' + error.message);
        }
    });
    
    let cancelAdminPasswordChangeClickTime = 0;
    document.getElementById('btnCancelAdminPasswordChange')?.addEventListener('click', () => {
        const now = Date.now();
        if (now - cancelAdminPasswordChangeClickTime < 500) return;
        cancelAdminPasswordChangeClickTime = now;
        
        try {
            document.getElementById('adminPasswordChangeModal').classList.add('hidden');
            // 입력 필드 초기화
            document.getElementById('currentAdminPassword').value = '';
            document.getElementById('newAdminPassword').value = '';
            document.getElementById('confirmNewAdminPassword').value = '';
        } catch (error) {
            alert('모달 닫기 중 오류 발생: ' + error.message);
        }
    });
    
    // 관리자 비밀번호 변경 모달에서 Enter 키
    document.getElementById('confirmNewAdminPassword').addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            document.getElementById('btnConfirmAdminPasswordChange').click();
        }
    });
});
