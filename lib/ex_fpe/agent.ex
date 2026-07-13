# credo:disable-for-this-file Credo.Check.Readability.ModuleNames
defmodule ExFPE.Agent do
  @moduledoc false
  # Storage for a `ExFPE` context shared across a supervision tree.
  #
  # Like stdlib's `Agent` but backed by OTP's `:persistent_term`, so reads are
  # lock-free. Used by the `use ExFPE` macro; you shouldn't need it directly.

  use GenServer

  require Record

  ## Types

  @typedoc false
  @type shared_state_init :: {function(), [term()]}

  @typep init_args :: [
           module: module,
           shared_state_init: shared_state_init
         ]

  Record.defrecordp(:state, [:shared_state_key])

  @typep state :: record(:state, shared_state_key: term)

  ## API

  @doc false
  @spec child_spec(module, {module, atom, [term]}) :: Supervisor.child_spec()
  def child_spec(module, mfa) do
    %{
      id: module,
      start: mfa,
      modules: [__MODULE__]
    }
  end

  @doc false
  @spec start_link(module, shared_state_init) :: {:ok, pid} | {:error, term}
  def start_link(module, shared_state_init) do
    init_args = [
      module: module,
      shared_state_init: shared_state_init
    ]

    :proc_lib.start_link(__MODULE__, :proc_lib_init, [init_args])
  end

  @doc false
  @spec get(module) :: {:ok, ExFPE.t()} | {:error, {:ctx_not_found_for_module, module}}
  def get(module) do
    shared_state_key = shared_state_key(module)

    try do
      :persistent_term.get(shared_state_key)
    catch
      :error, :badarg when is_atom(module) ->
        {:error, {:ctx_not_found_for_module, module}}
    else
      ex_fpe ->
        {:ok, ex_fpe}
    end
  end

  @doc false
  @spec stop(pid, term) :: :ok
  def stop(pid, reason \\ :normal) do
    GenServer.stop(pid, reason, :infinity)
  end

  ## GenServer callbacks

  @doc false
  @spec proc_lib_init(init_args) :: no_return()
  def proc_lib_init(init_args) do
    module = Keyword.fetch!(init_args, :module)
    server_name = server_name(module)

    try do
      Process.register(self(), server_name)
    catch
      :error, %ArgumentError{} when is_atom(server_name) ->
        init_fail({:error, {:already_started, Process.whereis(server_name)}}, server_name)
    else
      true ->
        proc_lib_init_registered(init_args, module, server_name)
    end
  end

  @doc false
  @impl true
  @spec init(term) :: no_return()
  def init(_init_args) do
    raise "Initialization is done through proc_lib_init/1"
  end

  @doc false
  @impl true
  @spec terminate(term, state) :: term
  def terminate(reason, state) do
    # Keep shared state on unhealthy exits to avoid GC pressure from frequent
    # restarts when the crash reason won't go away by simply restarting.
    if not crashing?(reason) do
      shared_state_key = state(state, :shared_state_key)
      :persistent_term.erase(shared_state_key)
    end
  end

  ## Internal Functions

  defp proc_lib_init_registered(init_args, module, server_name) do
    {fun, args} = Keyword.fetch!(init_args, :shared_state_init)

    case apply(fun, args) do
      {:ok, ex_fpe} ->
        # Ensure terminate/2 runs unless we're killed
        _ = Process.flag(:trap_exit, true)

        shared_state_key = shared_state_key(module)
        :persistent_term.put(shared_state_key, ex_fpe)
        state = state(shared_state_key: shared_state_key)
        :proc_lib.init_ack({:ok, self()})

        :gen_server.enter_loop(
          __MODULE__,
          _enter_loop_opts = [],
          state,
          {:local, server_name},
          :hibernate
        )

      {:error, _} = error ->
        init_fail(error, server_name)
    end
  end

  defp init_fail(error, server_name) do
    # Use proc_lib.init_fail/2 rather than {:stop, reason} to keep logs clean:
    # our supervisor already reports the failed start.

    # Use apply/3 to avoid compilation warnings on OTP 25 or older.
    # credo:disable-for-next-line Credo.Check.Refactor.Apply
    apply(:proc_lib, :init_fail, [error, {:exit, :normal}])
  catch
    :error, :undef ->
      # Fallback for OTP 25 or older
      Process.unregister(server_name)
      :proc_lib.init_ack(error)
      :erlang.exit(:normal)
  end

  defp server_name(module) when is_atom(module) do
    String.to_atom("ex_fpe.agent." <> Atom.to_string(module))
  end

  defp shared_state_key(module) do
    {__MODULE__, module}
  end

  defp crashing?(reason) do
    case reason do
      :normal -> false
      :shutdown -> false
      {:shutdown, _} -> false
      _ -> true
    end
  end
end
