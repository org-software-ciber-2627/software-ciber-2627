import { pedirLista } from "./api-estado.js";
const SOAR_URL = "./mocks/soar-incidents.json";

export function getSOARIncidents() { 
    return pedirLista(SOAR_URL, (d) => d, "el SOAR"); // según el contrato con G6
}