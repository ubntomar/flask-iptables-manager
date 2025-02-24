
# Requisitos para ejecutar el script de administración de iptables

Para que el script funcione correctamente, es necesario instalar algunas dependencias. A continuación, se detallan los pasos para instalar estas dependencias en un entorno virtual de Python.

## Pasos para la instalación

1. **Crear un entorno virtual:**

    ```bash
    python3 -m venv venv
    ```

2. **Activar el entorno virtual:**

    ```bash
    source venv/bin/activate
    ```

3. **Instalar Flask:**

    ```bash
    pip install flask
    ```

4. **Instalar netifaces:**

    ```bash
    pip install netifaces
    ```

5. **Ejecutar la aplicación:**

    ```bash
    python3 app.py
    ```

## Notas adicionales

- Asegúrese de que el entorno virtual esté activado cada vez que desee ejecutar el script.
- Si necesita ejecutar el script con privilegios de superusuario, utilice el siguiente comando para mantener el entorno virtual activo:

    ```bash
    sudo venv/bin/python3 app.py
    ```

Siguiendo estos pasos, debería poder ejecutar el script sin problemas y gestionar las reglas de iptables a través de la interfaz web proporcionada por Flask.





# Configuración de iptables

## Instrucciones para hacer persistentes las reglas de iptables después de un reinicio:

1. **Guardar las reglas actuales de iptables en un archivo:**
    ```bash
    sudo iptables-save > /etc/iptables/rules.v4
    ```
    Para reglas IPv6, use:
    ```bash
    sudo ip6tables-save > /etc/iptables/rules.v6
    ```

2. **Instalar el paquete iptables-persistent para cargar automáticamente las reglas al iniciar:**
    ```bash
    sudo apt-get install iptables-persistent
    ```

3. **Durante la instalación, se le pedirá que guarde las reglas actuales. Confirme para guardarlas.**

4. **Si necesita guardar manualmente las reglas nuevamente en el futuro, use los siguientes comandos:**
    ```bash
    sudo netfilter-persistent save
    ```

5. **Para recargar manualmente las reglas, use:**
    ```bash
    sudo netfilter-persistent reload
    ```

6. **Asegúrese de que el servicio iptables-persistent esté habilitado para iniciarse al arrancar:**
    ```bash
    sudo systemctl enable netfilter-persistent
    ```
