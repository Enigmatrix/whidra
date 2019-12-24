import axios from "axios";
import { genRandomId } from "@/util";

export default axios.create({
  baseURL: "http://localhost:8080/api",
  headers: { SESS_ID: genRandomId(32) }
});
