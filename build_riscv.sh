#!/bin/sh

RISCV_TOOLS_SRC=${RISCV_TOOLS_SRC:="${HOME}/riscv-tools-netbsd"}
RISCV_TOOLS=${RISCV_TOOLS:="${HOME}/.riscv-tools"}
HOST=rv64
BFDDIR="${RISCV_TOOLS_SRC}/riscv-gnu-toolchain/riscv-binutils-gdb/build-binutils/bfd"
IBERTYDIR="${RISCV_TOOLS_SRC}/riscv-gnu-toolchain/riscv-binutils-gdb/build-binutils/libiberty"
EXTERNAL_TOOLCHAIN="${HOME}/netbsd/${HOST}/tools"

#Load NMAKES from environment, or figure it out
if [ "x$NMAKES" = "x" ]; then
  NMAKES=`sysctl hw.ncpuonline | sed 's/hw.ncpuonline = //g'`
  NMAKES=`expr $NMAKES \* 2`
fi

cd src

mkdir -p ../${HOST}/tools ../${HOST}/obj

./build.sh -m riscv64 -T ../${HOST}/tools -O ../${HOST}/obj \
		-X ../xsrc -U -u -j ${NMAKES} \
		-V BFDDIR="${BFDDIR}" \
		-V IBERTYDIR="${IBERTYDIR}" \
		-V TOOLCHAIN_MISSING="yes" \
		-V EXTERNAL_TOOLCHAIN="${EXTERNAL_TOOLCHAIN}" \
		-V NOGCCERROR="yes" \
		$@ &&

    if [ -z "${@##*tools*}" ] ; then
        echo "Creating symlinks to real tools..."
        ln -s "${RISCV_TOOLS}/bin/"* "${EXTERNAL_TOOLCHAIN}/bin/"
    fi &&

    if [ -z "${@##*kernel*}" ] ; then
        cd $RISCV_TOOLS_SRC &&
            ./netbsd_build.sh bbl-netbsd
    fi
