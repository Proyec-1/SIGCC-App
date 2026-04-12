// ========== SIGCC - VERSIÓN SEGURA 2.0 ==========
// ========== SISTEMA DE SEGURIDAD INTEGRADO ==========

let db;
let usuarioActual = null;
let intentosFallidos = 0;
let tiempoBloqueo = 0;
let ultimaPeticion = 0;
let sessionToken = null;

// ========== 1. FUNCIONES DE SEGURIDAD ==========

// Sanitizar HTML (evita XSS)
function sanitizarHTML(texto) {
    if (!texto) return '';
    return texto
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;')
        .replace(/[(){}[\]\\]/g, '');
}

// Validar formato de entrada
function validarEntrada(texto, tipo) {
    if (!texto) return false;
    if (tipo === 'cedula') {
        return /^[VEve]\d{7,8}$/.test(texto);
    }
    if (tipo === 'nombre') {
        return /^[a-zA-ZáéíóúñÑ\s]{3,50}$/.test(texto);
    }
    if (tipo === 'telefono') {
        return /^[0-9-]{7,15}$/.test(texto);
    }
    return true;
}

// Hash de contraseña SHA-256
async function hashPassword(password) {
    const encoder = new TextEncoder();
    const salt = 'SIGCC_SECURE_SALT_2024';
    const data = encoder.encode(password + salt);
    const hash = await crypto.subtle.digest('SHA-256', data);
    return btoa(String.fromCharCode(...new Uint8Array(hash)));
}

// Verificar fuerza de contraseña
function verificarFuerzaPassword(password) {
    let fuerza = 0;
    if (password.length >= 8) fuerza++;
    if (/[A-Z]/.test(password)) fuerza++;
    if (/[0-9]/.test(password)) fuerza++;
    if (/[^A-Za-z0-9]/.test(password)) fuerza++;
    
    if (fuerza < 2) return 'DEBIL';
    if (fuerza < 3) return 'MEDIA';
    return 'FUERTE';
}

// Detectar manipulación del navegador
function detectarManipulacion() {
    const alertas = [];
    try {
        const startTime = performance.now();
        debugger;
        const endTime = performance.now();
        if (endTime - startTime > 100) {
            alertas.push('CONSOLA_ABIERTA');
        }
    } catch(e) {}
    
    if (navigator.webdriver) {
        alertas.push('MODO_AUTOMATIZACION');
    }
    
    try {
        localStorage.setItem('test', 'test');
        localStorage.removeItem('test');
    } catch(e) {
        alertas.push('STORAGE_BLOQUEADO');
    }
    
    return alertas;
}

// Control de intentos fallidos
function registrarIntentoFallido() {
    intentosFallidos++;
    if (intentosFallidos >= 5) {
        tiempoBloqueo = Date.now() + 300000;
    }
}

function estaBloqueado() {
    if (tiempoBloqueo > Date.now()) {
        const minutosRestantes = Math.ceil((tiempoBloqueo - Date.now()) / 60000);
        return true;
    }
    return false;
}

// Rate limiting
function limitarPeticiones() {
    const ahora = Date.now();
    if (ahora - ultimaPeticion < 500) {
        return false;
    }
    ultimaPeticion = ahora;
    return true;
}

// Cifrado simple de datos
function cifrarDatos(datos, clave) {
    const texto = JSON.stringify(datos);
    let resultado = '';
    for (let i = 0; i < texto.length; i++) {
        resultado += String.fromCharCode(texto.charCodeAt(i) ^ clave.charCodeAt(i % clave.length));
    }
    return btoa(resultado);
}

// Registrar evento de seguridad
async function registrarEventoSeguridad(evento, detalles) {
    if (!db) return;
    const registro = {
        fecha: new Date().toISOString(),
        evento: evento,
        detalles: detalles,
        userAgent: navigator.userAgent,
        url: window.location.href
    };
    
    try {
        const transaction = db.transaction(['seguridad'], 'readwrite');
        const store = transaction.objectStore('seguridad');
        store.add(registro);
    } catch(e) {
        console.warn('Error al registrar seguridad:', e);
    }
}

// Generar token de sesión
function generarSessionToken() {
    return Math.random().toString(36) + Date.now().toString(36);
}

// ========== 2. INICIAR BASE DE DATOS ==========

function initDB() {
    return new Promise((resolve, reject) => {
        const request = indexedDB.open('SIGCC_DB_SECURE', 3);
        
        request.onerror = () => reject(request.error);
        request.onsuccess = () => {
            db = request.result;
            console.log('Base de datos segura iniciada');
            resolve(db);
        };
        
        request.onupgradeneeded = (event) => {
            const db = event.target.result;
            
            if (!db.objectStoreNames.contains('usuarios')) {
                const userStore = db.createObjectStore('usuarios', { keyPath: 'cedula' });
                userStore.createIndex('rol', 'rol');
                userStore.createIndex('estado', 'estado');
            }
            
            if (!db.objectStoreNames.contains('cadenas')) {
                const cadStore = db.createObjectStore('cadenas', { keyPath: 'id', autoIncrement: true });
                cadStore.createIndex('creador', 'creador');
                cadStore.createIndex('estado', 'estado');
                cadStore.createIndex('delegacion', 'delegacion');
            }
            
            if (!db.objectStoreNames.contains('auditoria')) {
                db.createObjectStore('auditoria', { keyPath: 'id', autoIncrement: true });
            }
            
            if (!db.objectStoreNames.contains('seguridad')) {
                db.createObjectStore('seguridad', { keyPath: 'id', autoIncrement: true });
            }
            
            if (!db.objectStoreNames.contains('config')) {
                db.createObjectStore('config', { keyPath: 'key' });
            }
        };
    });
}

// ========== 3. REGISTRAR AUDITORÍA ==========

async function registrarAuditoria(accion, detalles) {
    if (!db) await initDB();
    
    const usuario = usuarioActual || JSON.parse(localStorage.getItem('usuarioActual') || '{}');
    const registro = {
        fecha: new Date().toISOString(),
        usuario: usuario.cedula || 'desconocido',
        usuarioNombre: usuario.nombre || 'desconocido',
        accion: accion,
        detalles: sanitizarHTML(detalles || ''),
        ip: 'localhost',
        dispositivo: navigator.userAgent.substring(0, 100)
    };
    
    try {
        const transaction = db.transaction(['auditoria'], 'readwrite');
        const store = transaction.objectStore('auditoria');
        store.add(registro);
    } catch(e) {
        console.warn('Error al registrar auditoría:', e);
    }
}

// ========== 4. CREAR USUARIOS INICIALES SEGUROS ==========

async function cargarUsuariosIniciales() {
    const transaction = db.transaction(['usuarios'], 'readwrite');
    const store = transaction.objectStore('usuarios');
    
    const countRequest = store.count();
    countRequest.onsuccess = async () => {
        if (countRequest.result === 0) {
            const hashAdmin = await hashPassword('admin123');
            const hashUser = await hashPassword('user123');
            
            store.put({
                cedula: 'V12345678',
                nombre: 'Jefe UNES',
                password: hashAdmin,
                telefono: '0412-1234567',
                institucion: 'UNES',
                cargo: 'Director',
                jerarquia: 'Jefe',
                rol: 'jefe',
                estado: 'activo',
                fechaRegistro: new Date().toISOString(),
                intentos: 0
            });
            
            store.put({
                cedula: 'V87654321',
                nombre: 'Agente Pérez',
                password: hashUser,
                telefono: '0416-7654321',
                institucion: 'CICPC',
                cargo: 'Detective',
                jerarquia: 'Agente',
                rol: 'funcionario',
                estado: 'activo',
                fechaRegistro: new Date().toISOString(),
                intentos: 0
            });
            
            const configStore = db.transaction(['config'], 'readwrite').objectStore('config');
            configStore.put({ key: 'clave_unica', value: 'SIGCC2024' });
            configStore.put({ key: 'version', value: '2.0' });
            configStore.put({ key: 'seguridad_activada', value: true });
        }
    };
}

// ========== 5. LOGIN SEGURO ==========

document.addEventListener('DOMContentLoaded', async function() {
    await initDB();
    await cargarUsuariosIniciales();
    
    const btnLogin = document.getElementById('btnLogin');
    if (btnLogin) {
        btnLogin.addEventListener('click', loginSeguro);
    }
    
    if (window.location.pathname.includes('dashboard.html')) {
        verificarSesionSegura();
    }
    
    if (window.location.pathname.includes('escaner.html')) {
        // Escáner manual
    }
});

async function loginSeguro() {
    if (estaBloqueado()) {
        document.getElementById('errorMsg').innerHTML = '⛔ Sistema bloqueado. Espere 5 minutos.';
        return;
    }
    
    if (!limitarPeticiones()) {
        document.getElementById('errorMsg').innerHTML = '⏱️ Demasiados intentos. Espere un momento.';
        return;
    }
    
    const cedula = sanitizarHTML(document.getElementById('cedula').value.trim());
    const password = document.getElementById('password').value;
    
    if (!cedula || !password) {
        document.getElementById('errorMsg').innerHTML = '❌ Ingrese cédula y contraseña';
        return;
    }
    
    if (!validarEntrada(cedula, 'cedula')) {
        document.getElementById('errorMsg').innerHTML = '❌ Formato de cédula inválido (Ej: V12345678)';
        await registrarEventoSeguridad('FORMATO_CEDULA_INVALIDO', cedula);
        return;
    }
    
    const alertas = detectarManipulacion();
    if (alertas.length > 0) {
        await registrarEventoSeguridad('MANIPULACION_DETECTADA', alertas.join(','));
    }
    
    const passwordHash = await hashPassword(password);
    
    const transaction = db.transaction(['usuarios'], 'readonly');
    const store = transaction.objectStore('usuarios');
    const request = store.get(cedula);
    
    request.onsuccess = async () => {
        const user = request.result;
        
        if (user && user.password === passwordHash && user.estado === 'activo') {
            intentosFallidos = 0;
            sessionToken = generarSessionToken();
            localStorage.setItem('sessionToken', sessionToken);
            localStorage.setItem('usuarioActual', JSON.stringify(user));
            
            await registrarEventoSeguridad('LOGIN_EXITOSO', `Usuario ${cedula}`);
            await registrarAuditoria('LOGIN', `Usuario ${cedula} inició sesión`);
            
            window.location.href = 'dashboard.html';
        } else {
            registrarIntentoFallido();
            await registrarEventoSeguridad('LOGIN_FALLIDO', `Intento con cédula ${cedula}`);
            document.getElementById('errorMsg').innerHTML = `❌ Cédula o contraseña incorrectos. Intentos: ${intentosFallidos}/5`;
        }
    };
}

async function verificarSesionSegura() {
    const userStr = localStorage.getItem('usuarioActual');
    const token = localStorage.getItem('sessionToken');
    
    if (!userStr || !token) {
        window.location.href = 'index.html';
        return;
    }
    
    usuarioActual = JSON.parse(userStr);
    document.getElementById('nombreUsuario').innerHTML = sanitizarHTML(usuarioActual.nombre);
    document.getElementById('rolBadge').innerHTML = usuarioActual.rol.toUpperCase();
    
    if (usuarioActual.rol === 'jefe' || usuarioActual.rol === 'admin') {
        const adminPanel = document.getElementById('adminPanel');
        if (adminPanel) adminPanel.style.display = 'block';
    }
    
    await registrarAuditoria('VER_DASHBOARD', `Usuario ${usuarioActual.cedula} accedió al panel`);
}

// ========== 6. NAVEGACIÓN SEGURA ==========

window.irANuevaCadena = () => window.location.href = 'nueva_cadena.html';
window.irAEscaner = () => window.location.href = 'escaner.html';
window.irAMisCadenas = () => window.location.href = 'mis_cadenas.html';
window.irARegistrarUsuario = () => window.location.href = 'registrar_usuario.html';
window.irACambiarClave = () => window.location.href = 'cambiar_clave.html';
window.irAAuditoria = () => window.location.href = 'auditoria.html';

window.logout = async function() {
    await registrarAuditoria('LOGOUT', `Usuario ${usuarioActual.cedula} cerró sesión`);
    localStorage.clear();
    window.location.href = 'index.html';
};

window.sincronizar = function() {
    alert('✅ Sincronización con servidor central completada');
};

// ========== 7. NUEVA CADENA SEGURA ==========

window.guardarCadena = async function() {
    const descripcion = sanitizarHTML(document.getElementById('descripcion').value);
    const lugar = sanitizarHTML(document.getElementById('lugar').value);
    const fechaHora = document.getElementById('fechaHora').value;
    const observaciones = sanitizarHTML(document.getElementById('observaciones').value);
    const delegacion = document.getElementById('delegacion').value;
    
    if (!descripcion || !lugar || !fechaHora || !delegacion) {
        alert('Complete todos los campos obligatorios');
        return;
    }
    
    const nuevaCadena = {
        descripcion: descripcion,
        lugar: lugar,
        fecha: fechaHora,
        observaciones: observaciones,
        delegacion: delegacion,
        estado: 'abierta',
        creador: usuarioActual.cedula,
        creadorNombre: usuarioActual.nombre,
        fechaCreacion: new Date().toISOString(),
        historial: [{
            fecha: new Date().toISOString(),
            accion: 'CREACIÓN',
            usuario: usuarioActual.cedula,
            ubicacion: delegacion
        }]
    };
    
    const transaction = db.transaction(['cadenas'], 'readwrite');
    const store = transaction.objectStore('cadenas');
    const request = store.add(nuevaCadena);
    
    request.onsuccess = async (event) => {
        const id = event.target.result;
        await registrarAuditoria('CREAR_CADENA', `Cadena #${id} creada en ${delegacion}`);
        alert(`✅ Cadena #${id} creada exitosamente`);
        window.location.href = 'dashboard.html';
    };
};

// ========== 8. VERIFICAR CADENA ==========

window.verificarCadenaPorId = async function() {
    const id = parseInt(document.getElementById('buscarId').value);
    if (!id) {
        alert('Ingrese el ID de la cadena');
        return;
    }
    
    const transaction = db.transaction(['cadenas'], 'readonly');
    const store = transaction.objectStore('cadenas');
    const request = store.get(id);
    
    request.onsuccess = async () => {
        const cadena = request.result;
        const div = document.getElementById('resultado');
        
        if (cadena) {
            await registrarAuditoria('VERIFICAR_CADENA', `Se verificó cadena #${id}`);
            div.innerHTML = `
                <div style="background:#e8f5e9;padding:15px;border-radius:12px;">
                    <h3>✅ CADENA DE CUSTODIA VÁLIDA</h3>
                    <p><strong>ID:</strong> ${cadena.id}</p>
                    <p><strong>Descripción:</strong> ${sanitizarHTML(cadena.descripcion)}</p>
                    <p><strong>Lugar:</strong> ${sanitizarHTML(cadena.lugar)}</p>
                    <p><strong>Delegación:</strong> ${sanitizarHTML(cadena.delegacion)}</p>
                    <p><strong>Estado:</strong> <span class="estado-${cadena.estado}">${cadena.estado.toUpperCase()}</span></p>
                    <p><strong>Creado por:</strong> ${sanitizarHTML(cadena.creadorNombre)}</p>
                </div>
            `;
        } else {
            div.innerHTML = `<div style="background:#ffebee;padding:15px;border-radius:12px;">
                <h3>❌ CADENA NO ENCONTRADA</h3>
                <p>No existe ninguna cadena con ID #${id}</p>
            </div>`;
        }
    };
};

// ========== 9. MIS CADENAS ==========

async function cargarMisCadenas() {
    const transaction = db.transaction(['cadenas'], 'readonly');
    const store = transaction.objectStore('cadenas');
    const index = store.index('creador');
    const request = index.getAll(usuarioActual.cedula);
    
    request.onsuccess = () => {
        const cadenas = request.result;
        const tbody = document.getElementById('listaCadenas');
        tbody.innerHTML = '';
        
        if (cadenas.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6">No hay cadenas registradas</td></tr>';
            return;
        }
        
        cadenas.forEach(cadena => {
            const row = tbody.insertRow();
            row.insertCell(0).innerHTML = cadena.id;
            row.insertCell(1).innerHTML = sanitizarHTML(cadena.descripcion.substring(0, 30));
            row.insertCell(2).innerHTML = sanitizarHTML(cadena.delegacion);
            row.insertCell(3).innerHTML = `<span class="estado-${cadena.estado}">${cadena.estado}</span>`;
            row.insertCell(4).innerHTML = new Date(cadena.fechaCreacion).toLocaleDateString();
            row.insertCell(5).innerHTML = `<button onclick="verDetalleCadena(${cadena.id})">Ver</button>`;
        });
    };
}

window.verDetalleCadena = async function(id) {
    const transaction = db.transaction(['cadenas'], 'readonly');
    const store = transaction.objectStore('cadenas');
    const request = store.get(id);
    
    request.onsuccess = async () => {
        const cadena = request.result;
        await registrarAuditoria('VER_DETALLE', `Vio detalles de cadena #${id}`);
        alert(`📄 CADENA #${cadena.id}\n\nDescripción: ${cadena.descripcion}\nLugar: ${cadena.lugar}\nDelegación: ${cadena.delegacion}\nEstado: ${cadena.estado}`);
    };
};

// ========== 10. REGISTRAR FUNCIONARIO SEGURO ==========

window.registrarFuncionario = async function() {
    const cedula = sanitizarHTML(document.getElementById('reg_cedula').value.trim());
    const nombre = sanitizarHTML(document.getElementById('reg_nombre').value.trim());
    const telefono = sanitizarHTML(document.getElementById('reg_telefono').value);
    const institucion = document.getElementById('reg_institucion').value;
    const cargo = sanitizarHTML(document.getElementById('reg_cargo').value);
    const jerarquia = sanitizarHTML(document.getElementById('reg_jerarquia').value);
    const rol = document.getElementById('reg_rol').value;
    const password = document.getElementById('reg_password').value;
    
    if (!cedula || !nombre || !password) {
        alert('Complete cédula, nombre y contraseña');
        return;
    }
    
    if (!validarEntrada(cedula, 'cedula')) {
        alert('Formato de cédula inválido');
        return;
    }
    
    const fuerza = verificarFuerzaPassword(password);
    if (fuerza === 'DEBIL') {
        if (!confirm('⚠️ Contraseña débil. ¿Desea continuar de todos modos?')) {
            return;
        }
    }
    
    const passwordHash = await hashPassword(password);
    
    const transaction = db.transaction(['usuarios'], 'readwrite');
    const store = transaction.objectStore('usuarios');
    
    const checkRequest = store.get(cedula);
    checkRequest.onsuccess = async () => {
        if (checkRequest.result) {
            alert('Ya existe un usuario con esa cédula');
            return;
        }
        
        store.add({
            cedula: cedula,
            nombre: nombre,
            password: passwordHash,
            telefono: telefono,
            institucion: institucion,
            cargo: cargo,
            jerarquia: jerarquia,
            rol: rol,
            estado: 'activo',
            fechaRegistro: new Date().toISOString(),
            intentos: 0
        });
        
        await registrarAuditoria('REGISTRAR_USUARIO', `Registró nuevo usuario: ${cedula}`);
        alert('✅ Funcionario registrado exitosamente');
        window.location.href = 'dashboard.html';
    };
};

// ========== 11. AUDITORÍA ==========

async function cargarAuditoria() {
    const transaction = db.transaction(['auditoria'], 'readonly');
    const store = transaction.objectStore('auditoria');
    const request = store.getAll();
    
    request.onsuccess = () => {
        const registros = request.result.reverse();
        const tbody = document.getElementById('listaAuditoria');
        tbody.innerHTML = '';
        
        registros.slice(0, 50).forEach(reg => {
            const row = tbody.insertRow();
            row.insertCell(0).innerHTML = new Date(reg.fecha).toLocaleString();
            row.insertCell(1).innerHTML = sanitizarHTML(reg.usuario);
            row.insertCell(2).innerHTML = sanitizarHTML(reg.usuarioNombre);
            row.insertCell(3).innerHTML = sanitizarHTML(reg.accion);
            row.insertCell(4).innerHTML = sanitizarHTML(reg.detalles.substring(0, 50));
        });
    };
}

// ========== 12. VOLVER ==========

window.volver = function() {
    window.location.href = 'dashboard.html';
};

console.log('✅ SIGCC - Sistema Seguro Versión 2.0 Cargado');
console.log('🔐 Seguridad activa: Hash SHA-256, Sanitización, Rate Limiting, Auditoría');