from flask import Flask, render_template, request, redirect, url_for, jsonify
import netifaces  # Nueva importación
import subprocess




app = Flask(__name__)


def get_network_interfaces():
    """
    Obtiene la lista de interfaces de red disponibles en el sistema.
    Retorna: Lista de nombres de interfaces (e.g. ['eth0', 'wlan0', etc])
    """
    try:
        # Obtiene todas las interfaces disponibles
        interfaces = netifaces.interfaces()
        return interfaces
    except Exception as e:
        print(f"Error obteniendo interfaces de red: {e}")
        return []

@app.context_processor
def inject_interfaces():
    return dict(network_interfaces=get_network_interfaces())



# Función auxiliar para ejecutar comandos
def run_command(cmd):
    result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        print(f"Error ejecutando: {cmd}\n{result.stderr}")
    return result.stdout.strip()

#############################
# Funciones para la tabla filter
#############################
def get_filter_rules(chain):
    cmd = f"iptables -S {chain}"
    output = run_command(cmd)
    rules = []
    for line in output.splitlines():
        if line.startswith("-A"):
            parts = line.split()
            rule = {
                "source": "", 
                "destination": "", 
                "action": "",
                "protocol": "any"  # Valor por defecto
            }
            i = 0
            while i < len(parts):
                if parts[i] == "-s":
                    rule["source"] = parts[i+1]
                    i += 2
                elif parts[i] == "-d":
                    rule["destination"] = parts[i+1]
                    i += 2
                elif parts[i] == "-p":
                    rule["protocol"] = parts[i+1]
                    i += 2
                elif parts[i] == "-j":
                    act = parts[i+1]
                    if act.upper() == "ACCEPT":
                        rule["action"] = "permit"
                    elif act.upper() == "DROP":
                        rule["action"] = "deny"
                    else:
                        rule["action"] = act.lower()
                    i += 2
                else:
                    i += 1
            rules.append(rule)
    return rules

def flush_filter_chain(chain):
    run_command(f"iptables -F {chain}")

def add_filter_rule(chain, source, destination, action, protocol='any'):
    if action == "permit":
        target = "ACCEPT"
    elif action == "deny":
        target = "DROP"
    else:
        target = action.upper()
    
    # Construir el comando base
    cmd = f"iptables -A {chain}"
    
    # Agregar source y destination
    cmd += f" -s {source}" if source != 'any' else ''
    cmd += f" -d {destination}" if destination != 'any' else ''
    
    # Agregar protocolo si no es 'any'
    if protocol != 'any':
        cmd += f" -p {protocol}"
    
    # Agregar la acción
    cmd += f" -j {target}"
    
    run_command(cmd)

#############################
# Funciones para la tabla nat
#############################
def get_nat_rules(chain):
    cmd = f"iptables -t nat -S {chain}"
    output = run_command(cmd)
    rules = []
    for line in output.splitlines():
        if line.startswith("-A"):
            parts = line.split()
            # Se extraen algunos parámetros comunes
            rule = {"source": "", "destination": "", "protocol": "", "dport": "", "target": "", "to": "", "interface": ""}
            i = 0
            while i < len(parts):
                if parts[i] == "-s":
                    rule["source"] = parts[i+1]
                    i += 2
                elif parts[i] == "-d":
                    rule["destination"] = parts[i+1]
                    i += 2
                elif parts[i] == "-p":
                    rule["protocol"] = parts[i+1]
                    i += 2
                elif parts[i] == "--dport":
                    rule["dport"] = parts[i+1]
                    i += 2
                elif parts[i] == "-j":
                    rule["target"] = parts[i+1]
                    i += 2
                elif parts[i] == "--to-destination":
                    rule["to"] = parts[i+1]
                    i += 2
                elif parts[i] == "-o":
                    rule["interface"] = parts[i+1]
                    i += 2
                else:
                    i += 1
            rules.append(rule)
    return rules

def flush_nat_chain(chain):
    run_command(f"iptables -t nat -F {chain}")

def add_nat_rule(chain, nat_type, **kwargs):
    """
    Añade una regla NAT según el tipo especificado.
    
    Args:
        chain (str): Cadena NAT (PREROUTING, POSTROUTING)
        nat_type (str): Tipo de NAT (dnat, snat, masquerade)
        **kwargs: Argumentos específicos para cada tipo de NAT
    """
    # Según el tipo de NAT, se construye el comando
    if nat_type == "dnat":
        # Obtener parámetros para DNAT
        source = kwargs.get("source", "")
        protocol = kwargs.get("protocol", "tcp")
        dport = kwargs.get("dport", "")
        to_destination_ip = kwargs.get("to_destination_ip", "")
        to_destination_port = kwargs.get("to_destination_port", "")
        
        # Construir el destino completo (IP:PUERTO)
        to_destination = f"{to_destination_ip}:{to_destination_port}"
        
        # Construir el comando base
        cmd = f"iptables -t nat -A {chain}"
        
        # Agregar source si está especificado
        if source:
            cmd += f" -s {source}"
        
        # Agregar protocolo y puerto
        cmd += f" -p {protocol} --dport {dport}"
        
        # Agregar la acción DNAT y el destino
        cmd += f" -j DNAT --to-destination {to_destination}"
        
    elif nat_type == "snat":
        # Obtener parámetros para SNAT
        destination = kwargs.get("destination", "")
        to_source = kwargs.get("to_source", "")
        
        # Se asume la cadena POSTROUTING para SNAT
        cmd = f"iptables -t nat -A {chain}"
        
        # Agregar destino si está especificado
        if destination:
            cmd += f" -d {destination}"
        
        # Agregar la acción SNAT y el source
        cmd += f" -j SNAT --to-source {to_source}"
        
    elif nat_type == "masquerade":
        # Obtener parámetros para Masquerade
        interface = kwargs.get("interface", "")
        destination = kwargs.get("destination", "")
        
        # Construir el comando base
        cmd = f"iptables -t nat -A {chain}"
        
        # Agregar destino si está especificado
        if destination:
            cmd += f" -d {destination}"
        
        # Agregar interfaz si está especificada
        if interface:
            cmd += f" -o {interface}"
        
        # Agregar la acción Masquerade
        cmd += " -j MASQUERADE"
    
    else:
        raise ValueError(f"Tipo de NAT no soportado: {nat_type}")
    
    # Ejecutar el comando
    run_command(cmd)

#############################
# Rutas para administración de Filter
#############################
@app.route('/')
def index():
    return render_template("index.html")

# Gestión de cadenas filter (FORWARD, INPUT, OUTPUT)
@app.route('/filter/<chain>', methods=["GET", "POST"])
def filter_chain(chain):
    if chain not in ["FORWARD", "INPUT", "OUTPUT"]:
        return "Cadena inválida", 400
        
    if request.method == "POST":
        source = request.form.get("source")
        destination = request.form.get("destination")
        action = request.form.get("action")
        protocol = request.form.get("protocol", "any")
        
        if source and destination and action:
            add_filter_rule(chain, source, destination, action, protocol)
        return redirect(url_for("filter_chain", chain=chain))
    else:
        rules = get_filter_rules(chain)
        return render_template("filter.html", chain=chain, rules=rules)

@app.route('/filter/update_order/<chain>', methods=["POST"])
def update_filter_order(chain):
    new_order = request.json.get("rules")
    if not new_order:
        return jsonify({"status": "error", "message": "No se proporcionaron reglas"}), 400
    flush_filter_chain(chain)
    for rule in new_order:
        add_filter_rule(chain, rule.get("source"), rule.get("destination"), rule.get("action"))
    return jsonify({"status": "success"})

@app.route('/filter/delete/<chain>', methods=["POST"])
def delete_filter_rule(chain):
    # Se espera recibir el índice (basado en la posición en la tabla)
    index = int(request.json.get("index", -1))
    if index < 0:
        return jsonify({"status": "error", "message": "Índice inválido"}), 400
    rules = get_filter_rules(chain)
    if index >= len(rules):
        return jsonify({"status": "error", "message": "Índice fuera de rango"}), 400
    del rules[index]
    flush_filter_chain(chain)
    for rule in rules:
        add_filter_rule(chain, rule.get("source"), rule.get("destination"), rule.get("action"))
    return jsonify({"status": "success"})

#############################
# Rutas para administración de NAT
#############################
@app.route('/nat', methods=["GET"])
def nat_index():
    return render_template("nat.html")

# Gestión de reglas NAT en cadenas PREROUTING (DNAT) y POSTROUTING (SNAT/Masquerade)
@app.route('/nat/<chain>', methods=["GET", "POST"])
def nat_chain(chain):
    """
    Maneja las peticiones GET y POST para la configuración de reglas NAT.
    
    Args:
        chain (str): Cadena NAT (PREROUTING o POSTROUTING)
    """
    # Validar la cadena
    if chain not in ["PREROUTING", "POSTROUTING"]:
        return "Cadena NAT inválida", 400

    if request.method == "POST":
        nat_type = request.form.get("nat_type")  # dnat, snat, masquerade
        
        if nat_type == "dnat":
            # Obtener parámetros para DNAT
            source = request.form.get("source", "")
            protocol = request.form.get("protocol", "tcp")
            dport = request.form.get("dport")
            to_destination_ip = request.form.get("to_destination_ip")
            to_destination_port = request.form.get("to_destination_port", "80")
            
            # Validar parámetros requeridos
            if dport and to_destination_ip:
                add_nat_rule(
                    chain=chain,
                    nat_type="dnat",
                    source=source,
                    protocol=protocol,
                    dport=dport,
                    to_destination_ip=to_destination_ip,
                    to_destination_port=to_destination_port
                )
                
        elif nat_type == "snat":
            # Obtener parámetros para SNAT
            destination = request.form.get("destination")
            to_source = request.form.get("to_source")
            
            # Validar parámetros requeridos
            if destination and to_source:
                add_nat_rule(
                    chain=chain,
                    nat_type="snat",
                    destination=destination,
                    to_source=to_source
                )
                
        elif nat_type == "masquerade":
            # Obtener parámetros para Masquerade
            interface = request.form.get("interface", "")
            destination = request.form.get("destination", "")
            
            add_nat_rule(
                chain=chain,
                nat_type="masquerade",
                interface=interface,
                destination=destination
            )
        
        # Redirigir a la misma página después de procesar
        return redirect(url_for("nat_chain", chain=chain))
        
    else:  # GET request
        # Obtener reglas existentes y mostrar la plantilla
        rules = get_nat_rules(chain)
        return render_template(
            "nat_chain.html",
            chain=chain,
            rules=rules,
            network_interfaces=get_network_interfaces()
        )

@app.route('/nat/update_order/<chain>', methods=["POST"])
def update_nat_order(chain):
    new_order = request.json.get("rules")
    if not new_order:
        return jsonify({"status": "error", "message": "No se proporcionaron reglas"}), 400
    flush_nat_chain(chain)
    # Para reinsertar, se recorren las reglas (en este ejemplo se asume que la estructura de la regla es suficiente)
    for rule in new_order:
        target = rule.get("target", "").lower()
        if target == "dnat":
            source = rule.get("source", "")
            dport = rule.get("dport", "")
            to = rule.get("to", "")
            if dport and to:
                if source:
                    add_nat_rule(chain, "dnat", source=source, dport=dport, to_destination=to)
                else:
                    add_nat_rule(chain, "dnat", dport=dport, to_destination=to)
        elif target == "snat":
            destination = rule.get("destination", "")
            to_source = rule.get("to", "")
            if destination and to_source:
                add_nat_rule(chain, "snat", destination=destination, to_source=to_source)
        elif target == "masquerade":
            interface = rule.get("interface", "")
            add_nat_rule(chain, "masquerade", interface=interface)
    return jsonify({"status": "success"})

@app.route('/nat/delete/<chain>', methods=["POST"])
def delete_nat_rule(chain):
    index = int(request.json.get("index", -1))
    if index < 0:
        return jsonify({"status": "error", "message": "Índice inválido"}), 400
    rules = get_nat_rules(chain)
    if index >= len(rules):
        return jsonify({"status": "error", "message": "Índice fuera de rango"}), 400
    del rules[index]
    flush_nat_chain(chain)
    for rule in rules:
        target = rule.get("target", "").lower()
        if target == "dnat":
            source = rule.get("source", "")
            dport = rule.get("dport", "")
            to = rule.get("to", "")
            if dport and to:
                if source:
                    add_nat_rule(chain, "dnat", source=source, dport=dport, to_destination=to)
                else:
                    add_nat_rule(chain, "dnat", dport=dport, to_destination=to)
        elif target == "snat":
            destination = rule.get("destination", "")
            to_source = rule.get("to", "")
            if destination and to_source:
                add_nat_rule(chain, "snat", destination=destination, to_source=to_source)
        elif target == "masquerade":
            interface = rule.get("interface", "")
            add_nat_rule(chain, "masquerade", interface=interface)
    return jsonify({"status": "success"})

if __name__ == '__main__':
    app.run(debug=True)
