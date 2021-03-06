// RUN: mlir-opt %s -convert-linalg-to-loops -convert-scf-to-std -convert-linalg-to-llvm -lower-affine -convert-scf-to-std --convert-memref-to-llvm -convert-std-to-llvm | \
// RUN: mlir-cpu-runner -e main -entry-point-result=void \
// RUN:   -shared-libs=%mlir_integration_test_dir/libmlir_runner_utils%shlibext \
// RUN: | FileCheck %s

// RUN: mlir-opt %s -linalg-tile="linalg-tile-sizes=0,0,4" -convert-linalg-to-loops -convert-scf-to-std \
// RUN:   -convert-linalg-to-llvm -lower-affine -convert-scf-to-std --convert-memref-to-llvm -convert-std-to-llvm | \
// RUN: mlir-cpu-runner -e main -entry-point-result=void \
// RUN:   -shared-libs=%mlir_integration_test_dir/libmlir_runner_utils%shlibext \
// RUN: | FileCheck %s

// RUN: mlir-opt %s -test-conv-vectorization="tile-sizes=1,1,1,3,3" -convert-linalg-to-llvm -lower-affine -convert-scf-to-std -convert-vector-to-llvm --convert-memref-to-llvm -convert-std-to-llvm | \
// RUN: mlir-cpu-runner -e main -entry-point-result=void \
// RUN:   -shared-libs=%mlir_integration_test_dir/libmlir_runner_utils%shlibext \
// RUN: | FileCheck %s

// RUN: mlir-opt %s -linalg-tile="linalg-tile-sizes=0,0,4" \
// RUN:   -test-conv-vectorization="tile-sizes=1,1,1,3,3" -convert-linalg-to-llvm -lower-affine -convert-scf-to-std -convert-vector-to-llvm --convert-memref-to-llvm -convert-std-to-llvm | \
// RUN: mlir-cpu-runner -e main -entry-point-result=void \
// RUN:   -shared-libs=%mlir_integration_test_dir/libmlir_runner_utils%shlibext \
// RUN: | FileCheck %s

func private @print_memref_f32(memref<*xf32>)

// Creates and returns 3-D buffer of size (%s1, %s2, %s3) filled with the value %f
func @alloc_3d_filled_f32(%s1 : index, %s2 : index, %s3 : index, %f : f32) -> memref<?x?x?xf32> {
  %buf = memref.alloc(%s1, %s2, %s3) : memref<?x?x?xf32>
  linalg.fill(%f, %buf) : f32, memref<?x?x?xf32>
  return %buf : memref<?x?x?xf32>
}

func @conv_1d_input_ncw_filter_wcf(%arg0: memref<?x?x?xf32>, %arg1: memref<?x?x?xf32>, %arg2: memref<?x?x?xf32>) {
  linalg.conv_1d_input_ncw_filter_wcf {dilations = dense<1> : tensor<1xi64>,
                         strides = dense<1> : tensor<1xi64>}
     ins (%arg0, %arg1: memref<?x?x?xf32>, memref<?x?x?xf32>)
    outs (%arg2: memref<?x?x?xf32>)
  return
}

func @main() {
  %c0 = constant 0 : index
  %c1 = constant 1 : index
  %c3 = constant 3 : index
  %c6 = constant 6 : index
  %c8 = constant 8 : index
  %f10 = constant 10.00000e+00 : f32
  %val = constant 2.00000e+00 : f32
  %zero = constant 0.00000e+00 : f32

  %filter1D_ncw = call @alloc_3d_filled_f32(%c3, %c1, %c1, %val) : (index, index, index, f32) -> (memref<?x?x?xf32>)
  %in1D_ncw = call @alloc_3d_filled_f32(%c1, %c1, %c8, %val) : (index, index, index, f32) -> (memref<?x?x?xf32>)
  %out1D_ncw = call @alloc_3d_filled_f32(%c1, %c1, %c6, %zero) : (index, index, index, f32) -> (memref<?x?x?xf32>)

  memref.store %f10, %in1D_ncw[%c0, %c0, %c3] : memref<?x?x?xf32>
  call @conv_1d_input_ncw_filter_wcf(%in1D_ncw, %filter1D_ncw, %out1D_ncw) : (memref<?x?x?xf32>, memref<?x?x?xf32>, memref<?x?x?xf32>) -> ()
  %out1D_ncw_ = memref.cast %out1D_ncw : memref<?x?x?xf32> to memref<*xf32>
  call @print_memref_f32(%out1D_ncw_): (memref<*xf32>) -> ()

  memref.dealloc %filter1D_ncw : memref<?x?x?xf32>
  memref.dealloc %in1D_ncw : memref<?x?x?xf32>
  memref.dealloc %out1D_ncw : memref<?x?x?xf32>
  return
}

// CHECK:       Unranked Memref {{.*}}
// CHECK-NEXT:  [
// CHECK-SAME:   [
// CHECK-SAME:    [12, 28, 28, 28, 12, 12]
// CHECK-SAME:   ]
// CHECK-SAME:  ]
