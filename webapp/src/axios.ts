import axios from "axios";
import { SESS_ID } from "@/util";

export default axios.create({
  baseURL: "/api",
  headers: { SESS_ID }
});
