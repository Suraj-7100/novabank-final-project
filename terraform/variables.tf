variable "region" {
  type    = string
  default = "ap-south-1"
}
variable "project" {
  type    = string
  default = "bank"
}
variable "environment" {
  type    = string
  default = "dev"
}
variable "vpc_cidr" {
  type    = string
  default = "10.0.0.0/16"
}
variable "az_count" {
  type    = number
  default = 2
}
variable "container_port" {
  type    = number
  default = 8080
}
variable "image_tag" {
  type    = string
  default = "latest"
}
variable "desired_count" {
  type    = number
  default = 2
}
variable "task_cpu" {
  type    = number
  default = 256
}
variable "task_memory" {
  type    = number
  default = 512
}

# --- database ---
variable "db_instance_class" {
  type    = string
  default = "db.t4g.micro"
}
variable "db_allocated_storage" {
  type    = number
  default = 20
}
variable "db_multi_az" {
  type    = bool
  default = false
}
variable "db_deletion_protection" {
  type        = bool
  default     = false
  description = "Set true for production."
}
variable "db_skip_final_snapshot" {
  type        = bool
  default     = true
  description = "Set false for production."
}
variable "secret_recovery_window_days" {
  type        = number
  default     = 0
  description = "0 = delete secrets immediately on destroy (dev). Use 7-30 in production."
}


variable "cors_origin" {
  description = "Exact browser origin allowed to call the API, e.g. https://app.example.com"
  type        = string
  default     = "http://127.0.0.1:5500"
}
