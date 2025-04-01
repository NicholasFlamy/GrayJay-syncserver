provider "aws" {
  region = "us-east-1"
}

variable "instance_count" {
  description = "Number of instances to launch"
  type        = number
  default     = 10
}

variable "ssh_user" {
  description = "SSH user for the instances"
  type        = string
  default     = "ubuntu"
}

resource "aws_security_group" "allow_ssh" {
  name        = "allow_ssh"
  description = "Allow SSH inbound traffic"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "benchmark_instance" {
  count         = var.instance_count
  ami           = "ami-084568db4383264d4"
  instance_type = "t3.medium"
  key_name      = "koen@pop-os"
  associate_public_ip_address = true
  vpc_security_group_ids = [aws_security_group.allow_ssh.id]
  tags = {
    Name = "Benchmark-Instance-${count.index + 1}"
  }
  connection {
    type        = "ssh"
    user        = var.ssh_user
    host        = self.public_ip
    agent       = true
  }
  provisioner "file" {
    source      = "SyncClient"
    destination = "/home/${var.ssh_user}/SyncClient"
  }
  provisioner "remote-exec" {
    inline = [
      "chmod +x /home/${var.ssh_user}/SyncClient",
      "sudo apt update && sudo apt install libsodium-dev -y"
    ]
  }
}

output "instance_public_ips" {
  value = aws_instance.benchmark_instance[*].public_ip
}