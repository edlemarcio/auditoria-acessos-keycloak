#!/usr/bin/env bash
# Sobe os simuladores (instância 26.x, 18.x legado e três variantes de comportamento para as sondas)
cd "$(dirname "$0")/.." ; mkdir -p logs
up(){ env "$@" nohup uvicorn simulator.app:app --port "$PORTA" --log-level warning > "logs/sim-$PORTA.log" 2>&1 & }
PORTA=8126 up SIM_PERFIL=kc26 SIM_DSN=postgresql://postgres@127.0.0.1/kc26 SIM_PURGA_INTERVALO=300
PORTA=8118 up SIM_PERFIL=kc18 SIM_DSN=postgresql://postgres@127.0.0.1/kc18 SIM_TZ=America/Sao_Paulo
PORTA=8127 up SIM_PERFIL=kc26 SIM_DSN=postgresql://postgres@127.0.0.1/kc26 SIM_BUG_DATETO=1
PORTA=8128 up SIM_PERFIL=kc26 SIM_DSN=postgresql://postgres@127.0.0.1/kc26 SIM_SEM_DIRECTION=1
PORTA=8129 up SIM_PERFIL=kc26 SIM_DSN=postgresql://postgres@127.0.0.1/kc26 SIM_EXACT_CURINGA=1
PORTA=8130 up SIM_PERFIL=kc26 SIM_DSN=postgresql://postgres@127.0.0.1/kc26 SIM_PURGA_INTERVALO=15
sleep 4; for p in 8126 8118 8127 8128 8129 8130; do echo "$p $(curl -s localhost:$p/_sim/stats)"; done
