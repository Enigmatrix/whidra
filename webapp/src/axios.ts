import axios from "axios";
import { genRandomId } from "@/util";

export default axios.create({
  baseURL: "/api",
  headers: { SESS_ID: genRandomId(32) }
});
