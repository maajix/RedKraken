# NucleiFuzzer

Status: Erledigt

[https://github.com/0xKayala/NucleiFuzzer](https://github.com/0xKayala/NucleiFuzzer)

```bash
git clone https://github.com/0xKayala/NucleiFuzzer.git
cd NucleiFuzzer
sudo chmod +x install.sh
./install.sh
```

```bash
export DOMAIN = "example.com"
```

# Run NucleiFuzzer on a single domain

```bash
sudo nf -d $DOMAIN
```

# Run NucleiFuzzer on multiple domains

```bash
sudo nf -f <domain_list>
```

# View the output

```bash
mv output nuclei-fuzzer-scan && cd nuclei-fuzzer-scan
```