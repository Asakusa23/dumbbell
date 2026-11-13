def run(cmd)
  system("sh -c #{cmd}")
end

def load(data)
  Marshal.load(data)
end
